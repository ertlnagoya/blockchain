import mysql.connector
 
db=mysql.connector.connect(host="localhost", user="root", password="")

cursor=db.cursor()
 
cursor.execute("USE test_db")
db.commit()
cursor.execute("""CREATE TABLE IF NOT EXISTS fruits_table(
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                previous_hash VARCHAR(10000),
                proof INT,
                timestamq VARCHAR(32),
                transactions VARCHAR(1000));""")
db.commit()


cursor=db.cursor()
 
# データベース「test_db」を選択
cursor.execute("USE test_db")
db.commit()
 
# データを挿入
insert_fruit = "INSERT INTO fruits_table (previous_hash, proof, timestamq, transactions) VALUES (%s, %s, %s, %s);"
 
fruit = ("e3d1ca4f559d7993f6ef6a176b93bb".encode("UTF-8"), 
        10402, "1532488916.119005".encode("UTF-8"), 
        "[{counter: 1, recipient: someon".encode("UTF-8"))

for i in range(10000):
    cursor.execute(insert_fruit, fruit)
 
db.commit()
