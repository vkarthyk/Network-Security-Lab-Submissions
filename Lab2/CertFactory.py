
def getPrivateKeyForAddr(addr):
  # ignoring addr, always return the same thing
  with open("mykey.pem") as f:
        return f.read()

def getCertsForAddr(addr):
    chain = []
    with open(addr+".cert") as f:
        chain.append(f.read())
    with open("vkarthy1_signed.cert") as f_ca:
        chain.append(f_ca.read())
    return chain

def getRootCert():
    with open("20164_signed.cert") as f:
        return f.read()
