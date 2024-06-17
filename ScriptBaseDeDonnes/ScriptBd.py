import sqlite3

def createTable():
    connection = sqlite3.connect('tests.db')
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm VARCHAR(16) NOT NULL,
            taille INT NOT NULL,
            complexite INT NOT NULL,
            seed INT NOT NULL,
            success BOOLEAN NOT NULL,
            exectime INT NOT NULL
        )
    ''')

    connection.commit()
    connection.close()

def addTest(algorithm, taille, complexite, seed, success, exectime):
    connection = sqlite3.connect('tests.db')
    cursor = connection.cursor()

    cursor.execute('''
        INSERT INTO tests (algorithm, taille, complexite, seed, success, exectime)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (algorithm, taille, complexite, seed, success, exectime))

    connection.commit()
    connection.close()

def deleteLastTest():
    connection = sqlite3.connect('tests.db')
    cursor = connection.cursor()

    cursor.execute('''
        DELETE FROM tests WHERE id = (SELECT MAX(id) FROM tests)
    ''')

    connection.commit()
    connection.close()

def clearTable():
    connection = sqlite3.connect('tests.db')
    cursor = connection.cursor()

    cursor.execute('DELETE FROM tests')

    # Réinitialiser les identifiants autoincrement (facultatif)
    cursor.execute('DELETE FROM sqlite_sequence WHERE name="tests"')

    connection.commit()
    connection.close()

# Exemple d'utilisation des fonctions
createTable()
addTest('alg1', 100, 2, 42, True, 300)
deleteLastTest()
clearTable()
