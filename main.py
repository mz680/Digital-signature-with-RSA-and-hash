import rsa
import cryptography
import hashlib


def generate_key() :
    public_key, private_key = rsa.newkeys(2048)
    
    print("--- PUBLIC KEY ----")
    with open("public.pem", "wb") as f :
        f.write(public_key.save_pkcs1("PEM"))
    
    
    print("--- PRIVATE KEY ----")
    with open("private.pem", "wb") as f :
        f.write(private_key.save_pkcs1("PEM"))
        


def load_private_key(path="private.pem") :
    with open(path, "rb") as f :
        return rsa.PrivateKey.load_pkcs1(f.read())
    
def sign_file(file_path, private_key_path="private.pem") :
    private_key = load_private_key(private_key_path)
    
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f :
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    digest = sha256.digest()
    
    signature = rsa.sign_hash(digest, private_key, "SHA-256")
    
    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as f :
        f.write(signature)
        
    print(f"SHA-256 : {digest.hex()}")
    print(f"Digital Signature saved in : {sig_path}")
    return sig_path
    
    
def verify_file(file_path, signature_path, public_key_path="public.pem") :
    with open(public_key_path, "rb") as f :
        public_key = rsa.PublicKey.load_pkcs1(f.read())
        
    with open(file_path, "rb") as f :
        message = f.read()
    
    with open(signature_path, "rb") as f :
        signature = f.read()
        
    try :
        rsa.verify(message, signature, public_key)
        print("Valid")
        return True
    except rsa.VerificationError:
        print("Dokumen telah dimodifikasi atau palsu")
        return False
    
if __name__ == "__main__":
    generate_key()
    sign_file("coba.pdf")
    print("Start verify...")
    verify_file("coba.pdf", "coba.pdf.sig", "public.pem")