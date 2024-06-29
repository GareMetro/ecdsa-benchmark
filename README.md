# ecdsa-benchmark
Perform ECDSA and DSA Nonce Reuse private key recovery attacks

#### setup

Python 3.x:

```
#> virtualenv -p python3 .env3
#> . .env3/bin/activate
(.env3) #> python -m pip install -r requirements.txt
(.env3) #> python setup.py install
(.env3) #> python tests/test_ecdsa_key_recovery.py
```
Le venv est facultatif, et dans le cas ou pip ne peut pas performer l'installation automatique des dépendances, il est possible d'installer manuellement les 3 paquets du fichier `requirements.txt`

### Utilisation

Pour effectuer le benchmark, il suffit de lancer le script `benchmark.py`. Une fois le script terminé (l'exécution peut prendr eun certain temps), le fichier `tests.db` sera mis à jour avec les résultats obtenus. Le script `display.py` permet alors de produire des courbes. La base `TestsRapport.db` contient les résultats ayant produit les tests dans le rapport.