import sqlite3
from sqlite3 import Error

class DATABASE():

    def __init__ (self):
        self.create_connection(r"SNIFF.db")
        self.con = sqlite3.connect("SNIFF.db")
        self.cur = self.con.cursor()
        self.cur.execute('''
     
                   CREATE TABLE IF NOT EXISTS Packet
                   (
                   num int primary key,
                   date varchar(20),
                   length int,
                   macs varchar(20),
                   macd varchar(20),
                   ips varchar(20),
                   ipd varchar(20),
                   ports int,
                   portd int,
                   protocol varchar(20),
                   type varchar(20)
                   )
     
                   ''')


    def create_connection(self,db_file):
        # Create an SQLitedatabase connection
        conn = None
        try:
            conn = sqlite3.connect(db_file)
        except Error as e:
            print(e)
        finally:
            if conn:
                conn.close()


    def insert(self,num,date,length,macs,macd,ips,ipd,ports,portd,protocol,ptype):
        self.cur.execute("insert into Packet values(?,?,?,?,?,?,?,?,?,?,?)",(num,date,length,macs,macd,ips,ipd,ports,portd,protocol,ptype))


    def show (self):
        self.cur.execute('''select * from Packet''')
        trames= self.cur.fetchall()
        print(trames)


    def Commit(self):
        self.con.commit()

    def filter(self,req):
        requete="select * from Packet where " + req
        self.cur.execute(requete)
        return self.cur.fetchall()


