from ctypes import cdll

aes = cdll.LoadLibrary('./aes.dll')

f = open('config.yml','r')
data = f.read()
print("config.yml file")
print(data)
print("endfile")
data1 = bytes(2296)
print(type(data))
data_b1 = bytes(data, 'utf-8')
print(type(data_b1))
print(type(data1) )
print("byte data")
print(data_b1)
#data_b2 = bytes(data1, 'utf-8')
aes.AES_CBC_encrypt_File(data_b1, 'config1.bin')
aes.AES_CBC_decrypt_File(data1,'config1.bin')
print("dec result data1")
print(type(data1))
#dataout = data1.decode('utf-8', 'replace')
#dataout = data1.decode('utf-8', 'ignore')
#print(type(dataout))
#print(dataout)
print(data1)
print("end dec data1")
data2 =bytes(2296)
aes.AES_CBC_encrypt_File(data1, 'config1.bin')
aes.AES_CBC_decrypt_File(data2,'config1.bin')
print("dec result data2")
print(type(data2))
print(data2)
print("end dec data2")
data.close()