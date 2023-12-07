from Crypto.PublicKey import RSA


def generate_RSA():
    key = RSA.generate(2048)

    public_key = key.publickey().export_key()
    private_key = key.export_key()

    with open("public.pem", "wb") as file:
        file.write(public_key)

    with open("private.pem", "wb") as file:
        file.write(private_key)

    print("RSA keys generated successfully!")
