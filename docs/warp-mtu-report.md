# Rapport — `feat/warp-mtu`

## Dépôt et branche

- Fork : `https://github.com/johndoe237/opencode2api`
- Amont : `https://github.com/jasonxu114514/opencode2api`
- Branche locale : `feat/warp-mtu`
- Version de départ : `v1.4.7` (`b296a61`)
- Aucun push vers upstream, aucune issue et aucune PR créée.

## Architecture WARP vérifiée

Le gateway enregistre un compte WARP auprès de Cloudflare, crée un tunnel WireGuard userspace avec `wireguard-go`, puis termine le trafic dans la pile réseau userspace gVisor via `netstack.CreateNetTUN`. Le tunnel ne nécessite ni périphérique TUN, ni root, ni `NET_ADMIN`, ni modification de la table de routage ; le conteneur doit toutefois pouvoir envoyer de l’UDP vers les endpoints Cloudflare, notamment le port `2408`.

Le runtime crée un pool d’exits WARP dans `internal/gateway/runtime.go`. Chaque exit est enregistré par le registrar, construit dans `internal/warp/exit.go`, vérifié avec une requête Cloudflare Trace (`warp=on`), puis partagé entre les requêtes de trafic gratuit. Le pool est réutilisé lors d’un rechargement si sa clé de configuration ne change pas ; la nouvelle valeur MTU a donc été ajoutée à cette clé.

## Constat initial

La valeur MTU était bien codée en dur à `1280` dans :

```go
netstack.CreateNetTUN(localAddresses, dns, 1280)
```

Elle se trouvait dans `internal/warp/exit.go`, sans autre configuration MTU identifiée. Aucun réglage MSS séparé n’a été trouvé. La création du pool passait par `warp.Options`, puis `newExitWithStack`; ces deux points ont été adaptés pour propager la valeur.

## Modification réalisée

Ajout de `warp.mtu` :

- Type : entier JSON.
- Défaut effectif : `1280`, identique au comportement précédent lorsque le champ est absent ou vaut `0`.
- Bornes validées : `1000` à `1420` inclus.
- Valeur passée à `netstack.CreateNetTUN`.
- Une valeur MTU différente force un nouveau pool lors d’un hot reload.
- Le message d’échec de vérification WARP inclut désormais le MTU utilisé et conseille de réduire `warp.mtu` sur un chemin à MTU réduit.
- Le champ est intégré à la configuration stricte, à la normalisation, à la sauvegarde/relecture, à l’API d’administration, à la WebUI et à ses traductions anglaise, vietnamienne et italienne.

La limite haute `1420` est conservatrice et correspond à la valeur courante usuelle d’un tunnel WARP. La limite basse `1000` laisse une marge de réglage sans accepter des valeurs manifestement aberrantes. Un paquet WireGuard transporte environ 32 octets de surcharge propre au protocole, auxquels s’ajoutent 20 octets d’en-tête IPv4 + 8 UDP, soit environ **60 octets** sur IPv4, ou 40 octets IPv6 + 8 UDP + 32 WireGuard, soit environ **80 octets** sur IPv6. Pour un chemin MTU de 1316, cela donne environ `1256` de charge utile tunnel en IPv4 et `1236` en IPv6.

La contrainte IPv6 classique de MTU de lien de 1280 concerne normalement un lien IPv6 ; l’application de cette limite au MTU interne WARP dépend de la pile et du comportement de fragmentation. C’est pourquoi la configuration accepte 1200, mais cette valeur doit être validée avec le stack réellement utilisé. `1200` est la recommandation opérationnelle prudente pour Railway à partir des mesures fournies (`1300` OK, `1328` en échec), avec un compromis de surcharge et de débit légèrement supérieur.

## Fichiers modifiés

- `internal/config/config.go` — champ, défaut et validation.
- `internal/gateway/runtime.go` — propagation et invalidation de la réutilisation du pool.
- `internal/warp/exit.go` — constantes, validation, passage à `CreateNetTUN`, diagnostic.
- `internal/warp/pool.go` — option MTU et propagation à chaque exit.
- `internal/config/config_test.go` — défaut, valeur valide, bornes, rejet et round-trip.
- `internal/warp/pool_test.go` — rejet d’une valeur invalide avant toute inscription réseau.
- `config.example.json` — exemple avec `mtu: 1280`.
- `webui/index.html`, `webui/js/pages/config.js`, `webui/js/i18n.js` — édition WebUI et traductions.
- `README.md`, `README.zh-CN.md`, `README.vi.md`, `README.it.md` — tableaux de configuration et recommandation Railway.
- `docs/management.zh-CN.md` — guide de gestion.
- `docs/warp-mtu-report.md` — ce rapport.
- `docs/warp-mtu-issue.md` — brouillon d’issue en anglais.
- `docs/warp-mtu-pr.md` — brouillon de description de PR en anglais.

Le `Dockerfile` existant répond déjà au livrable demandé : multi-stage `golang:1.24-alpine` puis `alpine:3.22`, `CGO_ENABLED=0`, binaire compilé depuis le dépôt et utilisateur final `opencode2api` non-root. Il n’a pas été modifié car il était déjà conforme.

## Tests exécutés

| Commande | Résultat |
|---|---|
| `gofmt -w internal/config/config.go internal/config/config_test.go internal/warp/exit.go internal/warp/pool.go internal/warp/pool_test.go internal/gateway/runtime.go` | Réussie |
| `gofmt -l cmd internal webui` | Sortie vide, réussie |
| `go test ./...` | Réussie ; packages `internal/config` et `internal/warp` OK, autres packages sans tests |
| `go vet ./...` | Réussie, aucune sortie |
| `CGO_ENABLED=0 go build -o opencode2api ./cmd/opencode2api` | Réussie ; binaire ARM64 statique de 18 MiB dans le sandbox |
| `node --input-type=module --check < webui/js/*.js` et pages | Réussie |
| `sh -n docker-entrypoint.sh` | Réussie |
| `git diff --check` | Réussie |

Go `1.24.10` a été installé localement dans le sandbox pour ces contrôles, car Go n’y était pas préinstallé. Les dépendances ont été téléchargées normalement.

## Tests réseau non exécutés

Le sandbox ne dispose pas de Docker (`docker: command not found`) et je n’ai donc pas exécuté honnêtement :

- la reproduction de l’échec sur un réseau Docker MTU `1316` ;
- la matrice fonctionnelle `1420, 1280, 1256, 1240, 1200, 1100` avec `/healthz` ;
- le test IPv6 ;
- la confirmation empirique de la plus grande valeur fonctionnelle sur Railway.

La valeur `1200` est donc une recommandation raisonnée, pas un résultat réseau mesuré par cette exécution. Le `Dockerfile` peut être utilisé pour le test Railway demandé.

## Procédure Railway recommandée

1. Construire et déployer l’image depuis le fork, par exemple avec `docker build -t opencode2api-warp-mtu .`, ou utiliser le Dockerfile du dépôt dans Railway.
2. Conserver `warp.enabled: true`, `warp.stack: "ipv4"` et `warp.pool_size: 1` pour reproduire le cas fourni.
3. Ajouter dans `config.json` :

```json
"warp": {
  "enabled": true,
  "pool_size": 1,
  "stack": "ipv4",
  "mtu": 1200
}
```

4. Vérifier les logs de démarrage. En cas d’échec de vérification, le message doit contenir `tunnel MTU 1200` et le conseil de réduire `warp.mtu`.
5. Vérifier `GET /healthz`. Une initialisation réussie doit afficher un bloc `warp` actif et un statut prêt.
6. Pour mesurer la marge, tester successivement `1420`, `1280`, `1256`, `1240`, `1200` et `1100`, en conservant le même reste de configuration. Tester `stack: "ipv6"` séparément si l’IPv6 sortante est disponible.
7. Vérifier enfin qu’un fichier sans `warp.mtu` donne le comportement historique, c’est-à-dire un tunnel interne de `1280`.

## Risques et limites

- Un MTU trop élevé peut encore provoquer des pertes ou des timeouts TLS sur certains chemins ; un MTU trop bas augmente la fragmentation logique, la surcharge et peut réduire le débit.
- Le test de validité d’un exit reste dépendant de l’accès UDP Cloudflare, du DNS et de la connectivité IPv4/IPv6 de la plateforme.
- La borne basse `1000` est une garde raisonnable, pas une preuve que tous les stacks IPv6 fonctionneront correctement à cette valeur.
- Le `Dockerfile` n’a pas été modifié car il satisfaisait déjà le besoin ; le build d’image n’a pas été exécuté, Docker étant absent du sandbox.
