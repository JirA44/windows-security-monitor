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
| 1 — suspect | Déviation inhabituelle d’un utilisateur ou d’un composant, faible confiance ou portée limitée | Capturer les preuves, ralentir ou limiter la fonction identifiée, augmenter temporairement la fréquence des contrôles |
| 2 — élevé | Plusieurs signaux indépendants, ou identité, agent, processus, API, connecteur ou automatisation potentiellement compromis | Révoquer uniquement les identifiants concernés, isoler le compte ou le service atteint, bloquer la source selon une règle réversible |
| 3 — critique | Compromission probable du contrôle, du moniteur, d’une sauvegarde, d’une chaîne d’approvisionnement, altération active, exfiltration crédible ou intégrité impossible à établir | Déclencher le coupe-circuit du système ou du segment touché ; suspendre les opérations qui peuvent aggraver les pertes ; conserver les preuves |

Les règles exactes doivent être explicites, versionnées et testées. Les décisions automatiques doivent indiquer leurs signaux, leur score, la règle appliquée, l’action, l’heure et la méthode de retour arrière. Une absence de télémétrie, un journal corrompu ou une horloge incohérente doit dégrader la confiance et conduire à une posture sûre, pas à une conclusion « aucun incident ».

## Baselines comportementales de toutes les entités

Le comportement attendu doit être établi séparément pour chaque entité : utilisateur, compte de service, agent IA, processus, API, connecteur, bot, venue, file de tâches, base de données, sauvegarde, pipeline de build et composant de contrôle. Le profil tient compte du rôle, du composant, de l’opération, du volume, de la séquence, de l’heure et du contexte technique pertinent.

Toute déviation inexpliquée devient immédiatement un signal suspect, même seule : conserver les preuves, augmenter l’échantillonnage, vérifier l’entité et limiter uniquement l’opération sensible concernée. Une anomalie d’agent peut mettre en pause ses actions d’écriture tandis que ses fonctions de lecture restent disponibles. Une anomalie utilisateur peut demander une vérification renforcée. La déviation seule ne coupe pas tout le système ; des signaux indépendants, une compromission confirmée ou une altération critique font monter le niveau.

Protéger les baselines contre l’empoisonnement : ne pas apprendre d’une période suspecte, d’une session non vérifiée ou d’un incident ; conserver les versions, contrôler les mises à jour lentes et détecter les changements progressifs qui cherchent à déplacer la normale. En l’absence d’historique fiable, signaler le démarrage à froid et appliquer des limites prudentes. Minimiser les données stockées ; ne conserver ni secrets ni contenu privé qui n’est pas nécessaire à l’analyse.

## Coupe-circuit et retour arrière

- Prévoir des coupe-circuits distincts par service, compte, réseau et machine afin de limiter le rayon d’impact.
- Le niveau critique doit pouvoir couper temporairement l’accès ou les opérations risquées lorsque l’intégrité est douteuse.
- Toute coupure automatique doit être idempotente, journalisée et assortie d’une durée maximale ou d’une procédure de réévaluation.
- Le retour en ligne doit exiger des contrôles d’intégrité réussis et une version connue comme saine. Une simple expiration du délai ne prouve pas que la menace a disparu.
- La reprise peut être automatique, mais seulement après résolution de la cause, correction vérifiée, intégrité confirmée, absence de signal actif, au moins trois contrôles de santé consécutifs réussis et quinze minutes de période propre. Si des identifiants ont été compromis, leur rotation doit être confirmée.
- Réactiver uniquement le composant suspendu. Si un signal réapparaît pendant la reprise, le remettre immédiatement en pause. Ces seuils sont des paramètres initiaux à calibrer par système et à tester avec des incidents simulés.
- Garder une voie de récupération séparée et protégée. Le compte ou processus compromis ne doit pas pouvoir annuler son propre confinement ni supprimer les copies de sauvegarde.
- Ne jamais supprimer, écraser ou déplacer automatiquement des données en réponse à un signal incertain. Préserver les preuves et préférer l’isolation réversible.
- Les clés de trading, retraits et transferts de fonds doivent être désactivés ou révoqués selon une règle préétablie ; le moteur de réaction ne doit jamais initier de transfert de fonds.

## Scénarios de pire cas

La liste est un registre vivant, pas une promesse de couvrir chaque attaque imaginable. Chaque système doit cartographier ses actifs, frontières de confiance, dépendances et chemins de récupération, puis tester les combinaisons qui peuvent causer la plus grande perte.

- **Agents et essaims** : plusieurs agents coordonnent des requêtes, varient leur rythme, utilisent des instructions hostiles dans un dépôt, un ticket ou un journal, enchaînent des outils, puis tentent d’élargir leurs permissions ou de faire sortir des données.
- **Identités et isolation** : jeton volé/rejoué, compte administrateur compromis, escalade de privilèges, accès inter-utilisateur, compte de service détourné, usurpation d’un agent ou d’un connecteur.
- **Contrôle et détection** : surveillance arrêtée, règles modifiées, horloge décalée, journaux supprimés ou saturés, télémétrie retardée, coupe-circuit bloqué, canal de récupération perdu.
- **Propagation et dépendances** : paquet ou mise à jour compromise, pipeline de build détourné, jeton CI volé, artefact modifié, dépôt ou branche de référence compromis.
- **Données et sauvegardes** : exfiltration suivie d’effacement/chiffrement, sauvegarde en ligne détruite avec les données, manifeste falsifié, restauration contaminée, espace disque épuisé pendant la sauvegarde.
- **Défaillance de la réponse** : faux positif qui coupe le mauvais composant, actions de confinement en boucle, pause trop large, reprise avant correction, redémarrage qui enlève le confinement, incident qui revient juste après la reprise.
- **Pannes simultanées** : partition réseau/DNS, fournisseur indisponible, file saturée, événements dupliqués ou désordonnés, concurrence et courses d’état, panne de l’hôte pendant la remédiation.
- **Risque financier** : bot ou venue anormale, API de marché corrompue, clé de trading exposée, ordres qui se multiplient pendant une panne. Les campagnes restent en simulation ; aucune transaction réelle n’est permise.
- **Attaque sur l’intégrité de la campagne** : générateur de tests falsifié, graine ou historique modifié, rapport tronqué, tâche planifiée désactivée ou exécution annoncée alors qu’elle n’a pas eu lieu.

Combiner les scénarios par tests de propriétés et combinaisons pair-à-pair bornées, puis conserver les graines et les résultats. Les pires chaînes doivent inclure la défaillance simultanée du système surveillé, du moniteur et d’un mécanisme de récupération.

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
