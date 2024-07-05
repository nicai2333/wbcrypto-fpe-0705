# -*- coding: UTF-8 -*-
import mysql.connector

class CipherTypeError(Exception):
    def __init__(self, typename):
        self.typename = typename
    def __str__(self):
        return f"Type {self.typename} is out of range of cipher types. The list of premited types is (\"aes\", \"wbaes\", \"sm4\", \"wbsm4\", \"sm4_lut\", \"wbsm4_xl_la\", \"wbsm4_se_la\")"

class FFxError(Exception):
    def __init__(self, typename):
        self.typename = typename
    def __str__(self):
        return f"Type {self.typename} is out of range of ffx. The list of premited types is (\"ff1\", \"ff3\")"
    
class FFxError(Exception):
    def __init__(self, typename):
        self.typename = typename
    def __str__(self):
        return f"Type {self.typename} is out of range of ffx. The list of premited types is (\"ff1\", \"ff3\")"
    
class ModeError(Exception):
    def __init__(self, typename):
        self.typename = typename
    def __str__(self):
        return f"Type {self.typename} is out of range of mode. The list of premited types is (\"phone\", \"idcard\", \"address\")"

# 用fpe函数加密
class fpe_udf:

    # 初始化：创建 MySQL 数据库连接（根据所读取的mysql数据库修改即可）
    def __init__(self,hst,usr,pwd,dbase):
        self.db = mysql.connector.connect(
            host = hst,
            user = usr,
            password = pwd,
            database = dbase,
            auth_plugin = 'mysql_native_password'
        )
    
    def encrypt(self, mode, cipher, ffx):
            RangeOfCipher = {"aes", "wbaes", "sm4", "wbsm4", "sm4_lut", "wbsm4_xl_la", "wbsm4_se_la"}
            RangeOfFfx = {"ff1","ff3"}
            RangeOfMode = {"phone","idcard","address"}

            if cipher not in RangeOfCipher:
                raise CipherTypeError(cipher)
            if ffx not in RangeOfFfx:
                raise FFxError(ffx)
            if mode not in RangeOfMode:
                raise ModeError(mode)
            
            Cursor = self.db.cursor()
            search = "SELECT "+mode+",cast(fpe("+mode+",'"+mode+"','"+cipher+"','"+ffx+"') as char) from test.student limit 10"
            Cursor.execute(search)
            ciphertexts = Cursor.fetchall()
            plaintext = []
            ciphertext = []
            for row in ciphertexts:
                plaintext.append(row[0])  
                ciphertext.append(row[1])
            return plaintext,ciphertext

    # 加密单个字符串，返回加密串
    def encrypt_with_sample(self, mode, cipher, ffx, sample):
        RangeOfCipher = {"aes", "wbaes", "sm4", "wbsm4", "sm4_lut", "wbsm4_xl_la", "wbsm4_se_la"}
        RangeOfFfx = {"ff1","ff3"}
        RangeOfMode = {"phone","idcard","address"}

        if cipher not in RangeOfCipher:
            raise CipherTypeError(cipher)
        if ffx not in RangeOfFfx:
            raise FFxError(ffx)
        if mode not in RangeOfMode:
            raise ModeError(mode)
        
        Cursor = self.db.cursor()
        search = "SELECT "+mode+",cast(fpe("+mode+",'"+mode+"','"+cipher+"','"+ffx+"','"+sample+"') as char) from test.student limit 10"
        Cursor.execute(search)
        ciphertexts = Cursor.fetchall()
        plaintext = []
        ciphertext = []
        for row in ciphertexts:
            plaintext.append(row[0])  
            ciphertext.append(row[1])
        return plaintext,ciphertext
        

        


def test1(udf):
    mode = "phone"
    cipher = "aes"
    ffx = "ff1"
    sample = "139****5678"
    #这里根据访问的数据库的IP地址、用户名、密码、表名修改参数名即可
    plaintext,ciphertext = udf.encrypt_with_sample(mode,cipher,ffx,sample)
    for idx in range(10):
        print("plaintext:"+plaintext[idx]+"   ciphertext:"+ciphertext[idx])

def test2(udf):
    mode = "idcard"
    cipher = "wbaes"
    ffx = "ff3"
    sample = "4414**********1234"
    #这里根据访问的数据库的IP地址、用户名、密码、表名修改参数名即可

    plaintext,ciphertext = udf.encrypt_with_sample(mode,cipher,ffx,sample)
    for idx in range(10):
        print("plaintext:"+plaintext[idx]+"   ciphertext:"+ciphertext[idx])

def test3(udf):
    mode = "address"
    cipher = "sm4"
    ffx = "ff3"
    # sample = "**省**市**区*****"
    #地址加密暂时不支持sample，因为有自治区，自治县之类的单位，无法用一个sample对应所有情况

    plaintext,ciphertext = udf.encrypt(mode,cipher,ffx)
    for idx in range(10):
        print("plaintext:"+plaintext[idx]+"   ciphertext:"+ciphertext[idx])

if __name__ == "__main__":
    udf = fpe_udf("127.0.0.1","root","511511","test")
    test1(udf)
    test2(udf)
    test3(udf)



