# Réponse adaptative et campagnes quotidiennes de stress

## Statut

Cette spécification propose une évolution de WinDefend Toolkit. Elle ne signifie pas que le confinement ou les campagnes sont déjà actifs. L’activation exige une implémentation, des essais sur une machine de test, puis une intégration et une installation explicites.

## Objectif

Détecter et contenir automatiquement un incident avant qu’il ne se propage, en adaptant la réponse à sa gravité. Exécuter chaque jour des tests défensifs, y compris un scénario original, sans envoyer de trafic d’attaque vers des systèmes tiers ou vers la production.

Aucun test ne couvre toutes les attaques. Les campagnes doivent combiner contrôles connus, tests aléatoires bornés et scénarios inédits, et conserver leurs résultats pour mesurer les régressions.

## Niveaux de réponse

Les signaux doivent être évalués par confiance, impact, privilège concerné, étendue et intégrité des preuves. Une seule anomalie faible ne doit pas mettre la machine hors ligne.

| Niveau | Critères indicatifs | Réponse automatique |
|---|---|---|
| 0 — normal | Pas de signal pertinent | Continuer la surveillance et les contrôles |
| 1 — suspect | Anomalie isolée, faible confiance ou portée limitée | Capturer les preuves, ralentir ou limiter la fonction identifiée, augmenter temporairement la fréquence des contrôles |
| 2 — élevé | Plusieurs signaux indépendants, identité ou processus potentiellement compromis | Révoquer uniquement les identifiants concernés, isoler le compte ou le service atteint, bloquer la source selon une règle réversible |
| 3 — critique | Compromission probable d’un administrateur, altération active, exfiltration crédible, ou intégrité impossible à établir | Déclencher le coupe-circuit du système ou du segment touché ; suspendre les opérations qui peuvent aggraver les pertes ; conserver les preuves |

Les règles exactes doivent être explicites, versionnées et testées. Les décisions automatiques doivent indiquer leurs signaux, leur score, la règle appliquée, l’action, l’heure et la méthode de retour arrière. Une absence de télémétrie, un journal corrompu ou une horloge incohérente doit dégrader la confiance et conduire à une posture sûre, pas à une conclusion « aucun incident ».

## Coupe-circuit et retour arrière

- Prévoir des coupe-circuits distincts par service, compte, réseau et machine afin de limiter le rayon d’impact.
- Le niveau critique doit pouvoir couper temporairement l’accès ou les opérations risquées lorsque l’intégrité est douteuse.
- Toute coupure automatique doit être idempotente, journalisée et assortie d’une durée maximale ou d’une procédure de réévaluation.
- Le retour en ligne doit exiger des contrôles d’intégrité réussis et une version connue comme saine. Une simple expiration du délai ne prouve pas que la menace a disparu.
- Garder une voie de récupération séparée et protégée. Le compte ou processus compromis ne doit pas pouvoir annuler son propre confinement ni supprimer les copies de sauvegarde.
- Ne jamais supprimer, écraser ou déplacer automatiquement des données en réponse à un signal incertain. Préserver les preuves et préférer l’isolation réversible.
- Les clés de trading, retraits et transferts de fonds doivent être désactivés ou révoqués selon une règle préétablie ; le moteur de réaction ne doit jamais initier de transfert de fonds.

## Campagnes quotidiennes de stress et de sécurité

Chaque campagne quotidienne comprend :

1. **Contrôles fixes** : tests unitaires et d’intégration, analyse des dépendances et secrets, permissions, authentification, autorisation inter-utilisateurs, limites de débit, journaux et mécanismes de reprise.
2. **Scénarios de régression** : incidents passés et cas connus, rejoués avec des entrées non destructives.
3. **Fuzzing borné** : entrées malformées, tailles limites, séquences d’événements et concurrence, avec budgets CPU, mémoire, durée et volume.
4. **Un scénario original par jour** : généré à partir de la carte des menaces et des composants réellement présents. Enregistrer la graine, la variante, les préconditions et les assertions afin de pouvoir le rejouer.
5. **Test du dispositif de réponse** : injecter des signaux synthétiques dans un bac à sable et vérifier que le niveau choisi correspond à la politique, que l’action est réversible et que les journaux sont conservés.
6. **Test de restauration** : vérifier périodiquement la restauration d’une sauvegarde indépendante et comparer l’état restauré à un manifeste attendu.

### Scénarios originaux possibles

- Plusieurs signaux individuellement faibles, mais liés à une même identité ou fenêtre temporelle.
- Jeton valide utilisé depuis un contexte inhabituel, suivi d’un accès refusé à un autre compte.
- Redémarrage du service pendant un état de confinement, puis vérification que le coupe-circuit reste actif.
- Journal indisponible pendant une rafale de requêtes : vérifier que le système ne traite pas l’absence de preuve comme une preuve d’innocuité.
- Deux services qui redémarrent mutuellement et épuisent leurs ressources : vérifier le disjoncteur et les budgets.
- Changement d’heure, doublon d’événement ou événements reçus dans le désordre : vérifier que le score et les actions restent cohérents.

Les scénarios originaux doivent tester des hypothèses défensives. Ils ne doivent pas découvrir ou scanner des cibles publiques, tenter de voler des identifiants, déployer de charge utile, chiffrer des fichiers, supprimer des données, ou provoquer un déni de service réel.

## Environnements et garde-fous

- Exécuter les tests perturbateurs uniquement sur des machines jetables ou des environnements de préproduction autorisés, isolés des clés et données réelles.
- Utiliser des comptes, secrets, données et réseaux synthétiques. Refuser de démarrer si la cible n’est pas explicitement marquée comme environnement de test.
- Garder les scanners passifs en production ; limiter les vérifications actives de production à des contrôles de santé non destructifs et autorisés.
- Appliquer des plafonds de requêtes, de durée, de mémoire et de stockage. Arrêter un scénario dès qu’il sort de son périmètre.
- Ne pas exécuter de charges non fiables avec des permissions administrateur ou des secrets de production.

## Résultat attendu pour chaque campagne

Conserver un rapport horodaté contenant : commit testé, version des règles et outils, environnement, scénario et graine, résultats, durée, ressources, faux positifs, réaction observée, critères de succès et échecs. Une campagne incomplète, un scanner en panne ou une restauration non vérifiée doit être marqué **ÉCHEC/INCOMPLET**, jamais « sécurisé ».

Bloquer les changements qui introduisent une vulnérabilité critique ou élevée confirmée, une fuite de secret, un échec d’isolation entre utilisateurs, ou un coupe-circuit qui ne fonctionne pas. Les autres résultats doivent créer un dossier de correction avec priorité et preuve reproductible.

## Portée de WinDefend

La surveillance actuelle de processus et de persistance est un point de départ, pas une détection exhaustive. Les différences de baseline et les noms de processus seuls ne prouvent ni compromission ni innocuité. Le moteur adaptatif doit s’appuyer sur plusieurs signaux vérifiables et ne doit jamais tuer automatiquement un processus système sur la seule base de son nom.

## Plan de mise en œuvre

1. Ajouter un format d’événement et un journal append-only avec intégrité vérifiable.
2. Implémenter la politique de sévérité avec mode simulation par défaut.
3. Ajouter des actions isolables et réversibles, avec expiration et revalidation.
4. Créer des tests déterministes de la politique et du coupe-circuit.
5. Ajouter les campagnes quotidiennes sur runner isolé, incluant graine enregistrée et scénario original.
6. Éprouver sauvegarde, restauration et redémarrage pendant confinement.
7. N’activer l’application automatique que par environnement et après validation des faux positifs, des procédures de secours et des limites de ressources.

## English summary

Run bounded, isolated daily security and stress campaigns, including one seeded, replayable novel scenario each day. Use production telemetry for proportionate containment, with narrowly scoped reversible actions and a critical kill switch. Destructive tests must never target production or third-party systems. A missing or failed check is **incomplete**, not secure. This document is a proposal; it does not activate monitoring or containment.
