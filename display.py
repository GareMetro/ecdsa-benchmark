import sqlite3
import matplotlib.pyplot as plt

# Connect to the SQLite database
conn = sqlite3.connect('tests.db')
cursor = conn.cursor()

# Function to query data from the database
def query_data(query):
    cursor.execute(query)
    return cursor.fetchall()

# Query success rates and execution times
query_success_taille = """
    SELECT algorithm, taille, AVG(success) as success_rate
    FROM tests
    WHERE algorithm IN ('DSA', 'ECDSA')
    GROUP BY algorithm, taille
    ORDER BY taille;
"""

query_success_complexite = """
    SELECT algorithm, complexite, AVG(success) as success_rate
    FROM tests
    WHERE algorithm IN ('DSA', 'ECDSA')
    GROUP BY algorithm, complexite
    ORDER BY complexite;
"""

query_exectime_taille = """
    SELECT algorithm, taille, AVG(exectime) as avg_exectime
    FROM tests
    WHERE algorithm IN ('DSA', 'ECDSA')
    GROUP BY algorithm, taille
    ORDER BY taille;
"""

query_exectime_complexite = """
    SELECT algorithm, complexite, AVG(exectime) as avg_exectime
    FROM tests
    WHERE algorithm IN ('DSA', 'ECDSA')
    GROUP BY algorithm, complexite
    ORDER BY complexite;
"""

# Fetch data
success_taille_data = query_data(query_success_taille)
success_complexite_data = query_data(query_success_complexite)
exectime_taille_data = query_data(query_exectime_taille)
exectime_complexite_data = query_data(query_exectime_complexite)

# Close the connection
conn.close()

# Function to plot success rate
def plot_success_rate(data, x_label, title):
    plt.figure(figsize=(10, 6))
    for algorithm in ['DSA', 'ECDSA']:
        subset = [row for row in data if row[0] == algorithm]
        x = [row[1] for row in subset]
        y = [row[2] for row in subset]
        plt.plot(x, y, label=algorithm)
    plt.xlabel(x_label)
    plt.ylabel('Success Rate')
    plt.title(title)
    plt.legend()
    plt.show()

# Function to plot execution time
def plot_exectime(data, x_label, title):
    plt.figure(figsize=(10, 6))
    for algorithm in ['DSA', 'ECDSA']:
        subset = [row for row in data if row[0] == algorithm]
        x = [row[1] for row in subset]
        y = [row[2] for row in subset]
        plt.plot(x, y, label=algorithm)
    plt.xlabel(x_label)
    plt.ylabel('Execution Time (ms)')
    plt.title(title)
    plt.legend()
    plt.show()

# Plot success rate over taille
plot_success_rate(success_taille_data, 'Taille', 'Success Rate of DSA and ECDSA over Taille')

# Plot success rate over complexite
plot_success_rate(success_complexite_data, 'Complexite', 'Success Rate of DSA and ECDSA over Complexite')

# Plot execution time over taille
plot_exectime(exectime_taille_data, 'Taille', 'Execution Time of DSA and ECDSA over Taille')

# Plot execution time over complexite
plot_exectime(exectime_complexite_data, 'Complexite', 'Execution Time of DSA and ECDSA over Complexite')
