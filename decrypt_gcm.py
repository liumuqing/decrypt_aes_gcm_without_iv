import operator
from Crypto.Cipher import AES
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Util.number import long_to_bytes, bytes_to_long


def decrypt_aes_gcm_without_iv(key, ciphertext, authtext, auth_tag) -> bytes:
    aes = AES.new(key=key, mode=AES.MODE_GCM, nonce=b"x"*12) # this nonce is not used, I just need to put it here to make pycrypto happy.
    assert isinstance(aes, GcmMode)
    aes.update(authtext)
    aes._pad_cache_and_update()
    aes._update(ciphertext)
    aes._msg_len += len(ciphertext)
    #aes.digest()
    aes._pad_cache_and_update()
    aes._update(long_to_bytes(8 * aes._auth_len, 8))
    aes._update(long_to_bytes(8 * aes._msg_len, 8))
    s_tag = aes._signer.digest()
    assert len(s_tag) == len(auth_tag)
    j0_encrypted = bytes(map(lambda x: operator.xor(*x), zip(s_tag, auth_tag)))

    j0 = AES.new(key=key, mode=AES.MODE_ECB).decrypt(j0_encrypted)

    nonce_ctr = j0[:12]
    iv_ctr = (bytes_to_long(j0) + 1) & 0xFFFFFFFF
    aes_ctr = AES.new(key=key, mode=AES.MODE_CTR, initial_value=iv_ctr, nonce=nonce_ctr)
    p = aes_ctr.decrypt(ciphertext)
    return p


def test():
    iv = b"1" * 16
    key =  b"k" * 32
    aes = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    assert isinstance(aes, GcmMode)
    
    authtext = b"1234"
    aes.update(authtext)
    plaintext = b"this is plain text"
    ciphertext, auth_tag = aes.encrypt_and_digest(plaintext)
  
    aes = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    assert isinstance(aes, GcmMode)
    aes.update(authtext)
    plaintext1 = aes.decrypt_and_verify(ciphertext, auth_tag)
    print("decrypt by normal method: ", plaintext)


    plaintext2 = decrypt_aes_gcm_without_iv(key, ciphertext, authtext, auth_tag)
    print("decrypt without IV: ", plaintext2)


if __name__ == "__main__":
    test()
