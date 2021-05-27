def X_OR(operand1, operand2):   # XOR of two binary operands in string type
    if len(operand1) != len(operand2):
        print("ERROR : length of oprands of XOR must be the same!")
    else:
        result = []
        for i in range(len(operand1)):
            if ((operand1[i] == "0") and (operand2[i] == "0")) or ((operand1[i] == "1") and (operand2[i] == "1")):
                result.append("0")
            else:
                result.append("1")
        out_put = ''.join(str(e) for e in result)  # string
    return out_put

def ROTR(RotLength, operand):   # Right Rotation function (Length of rotation, string operand)
    rotLen = RotLength % len(operand)
    temp = operand[0:len(operand) - rotLen]
    result = operand[len(operand) - rotLen :] + temp
    return result

def SHR(shift_Length, operand):  # Shift right function (length of logical shift, string operand)
    shiftLen = shift_Length % len(operand)
    temp = operand[0:len(operand) - shiftLen]
    st_0 = "".join("0" for i in range(shiftLen))
    result = st_0 + temp
    return result

def sigma0(operand):  # sigma0 function : XOR of 3 values -- size = 64 bit
    temp = X_OR(ROTR(1, operand), ROTR(8, operand))
    result = X_OR(temp, SHR(7, operand))
    return result

def sigma1(operand):
    temp = X_OR(ROTR(19, operand), ROTR(61, operand))
    result = X_OR(temp, SHR(6, operand))
    return result

def andOp(operand1 , operand2):  # and of two binary string
    if len(operand1) != len(operand2):
        print("ERROR : length of oprands of AND must be the same!")
    else:
        result = []
        for i in range(len(operand1)):
            if operand1[i]=='1' and operand2[i]=='1' :
                result.append("1")
            else:
                result.append("0")
        out_put = ''.join(str(e) for e in result)
        return out_put

def notOp(operand):
    result = []
    for i in range(len(operand)):
        if operand[i]== "0" :
            result.append("1")
        elif operand[i]== "1" :
            result.append("0")
    out_put = ''.join(str(e) for e in result)
    return out_put

def Ch(opr1, opr2, opr3):  # Ch function(x, y, z)  : gets 3 operands
    tmp1 = andOp(opr1, opr2)
    tmp2 = andOp(notOp(opr1), opr3)
    result = X_OR(tmp1, tmp2)   # equals to :(x and y) xor (not(x) and z)
    return result

def Maj(opr1, opr2, opr3): # Maj function(x, y, z) : gets 3 operands
    tmp1 = andOp(opr1, opr2)
    tmp2 = andOp(opr1, opr3)
    tmp3 = andOp(opr2, opr3)
    result = X_OR(tmp1, tmp2)
    result = X_OR(result, tmp3) # equals to : (x and y) xor (x and z) xor (y and z)
    return result

def SIGMA0(operand):  # SIGMA0 function : XOR of 3 values -- size = 64 bit
    temp = X_OR(ROTR(28, operand), ROTR(34, operand))
    result = X_OR(temp, ROTR(39, operand))
    return result

def SIGMA1(operand):  # SIGMA0 function : XOR of 3 values -- size = 64 bit
    temp = X_OR(ROTR(14, operand), ROTR(18, operand))
    result = X_OR(temp, ROTR(41, operand))
    return result

def sha_func(prv_hash, new_block): # gets the previous hash and the new block of message (types are string)
    # Initialize array of round constants:
    # (first 32 bits of the fractional parts of the 3rd roots of the first 64 primes 2, 3, ..., 311):  (form the net)
    keys = [ 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
             0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
             0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
             0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
             0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
             0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
             0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
             0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
             0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
             0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
             0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
             0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
             0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
             0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
             0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
             0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
    # converting thr keys vector from hex to binary :
    K = []    # ROUND CONSTANTS    -- size = 80
    for x in range(80):
        temp = str(hex(keys[x]))
        keys[x] = temp[2:]
        K.append(bin(int(keys[x], 16))[2:].zfill(64))  # in scale of 16 converts the hex value to (64 bit) binary

    # words :
    Words = []   # size = 80 words (each word = 64 bit)
    for i in range(16):    # first 16 words are directly copied
        Words.append(new_block[i*64 : (i+1)*64])
    for j in range(16, 80):
        tmp1 = X_OR(sigma1(Words[j-2]), Words[j-7])
        tmp2 = X_OR(sigma0(Words[j-15]), Words[j-16])
        tmp = X_OR(tmp1, tmp2)
        Words.append(tmp)      # XOR of 4 values -- in 64 bit

    # rounds :
    A = prv_hash[0: 1*64]
    B = prv_hash[1*64 : 2*64]
    C = prv_hash[2*64 : 3*64]
    D = prv_hash[3*64 : 4*64]
    E = prv_hash[4*64 : 5*64]
    F = prv_hash[5*64 : 6*64]
    G = prv_hash[6*64 : 7*64]
    H = prv_hash[7*64 : 8*64]
    for x in range(80):
        t = X_OR(H, SIGMA1(E))
        t = X_OR(t, Ch(E, F, G))
        t = X_OR(t, Words[x])
        T1 = X_OR(t, K[x])    # Xor of 5 values : T1 =  H xor SIGMA1(E) xor Ch(E, F, G) xor W[x] xor K[x]
        T2 = X_OR(SIGMA0(A), Maj(A, B, C))   # T2 = SIGMA0(A) xor Maj(A, B, C)
        H = G
        G = F
        F = E
        E = X_OR(D, T1)
        D = C
        C = B
        B = A
        A = X_OR(T1, T2)
    out_put = A+B+C+D+E+F+G+H  # assembling A,B,C,D,E,F,G,H
    return out_put

def SHA_512(message):   # message type is binary!
    if len(message) > pow(2, 128):  # check message length limit
        print("the input size of SHA-2 is too long!")
        return 0
    else:
        if (len(message) % 1024) < 896:  # calculates padding length
            pad_len = 896 - (len(message) % 1024)
            pad = "0" * (pad_len - 1)
            pad = "1" + pad
            # 1st phase of SHA-512 algorithm :
            pad_msg = message + pad  # original message + padding
            msg_length = bin(len(message))[2:].zfill(128)    # converting the decimal length to binary
            str_msg_length = str(msg_length)
            # str_msg_length = str_msg_length[2:]  # removing "0b"!
            # 2nd phase of SHA-512 algorithm :
            SHA_MSG = pad_msg + str_msg_length  # message + padding + length
            """if len(SHA_MSG) % 1024 != 0 :
              print("error!!")"""
            n = len(SHA_MSG) / 1024  # n : number of blocks
            # 3rd phase of SHA-512 algorithm :
            # initial values vector --from net :
            iv = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, \
                  0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
            # converting the iv vector from hex to binary :
            IV = []
            for x in range(8):
                temp = str(hex(iv[x]))
                iv[x] = temp[2:]
                IV.append(bin(int(iv[x], 16))[2:].zfill(64)) # in scale of 16 converts the hex value to (64 bit) binary
            init_val = ''.join(str(e) for e in IV)  # 512 bit
            # 4th phase of SHA-512 algorithm :
            last_Hash = init_val    # for first block of message previous hash is initial value
            for i in range(int(n)):
                """if i == 0 :
                    last_Hash = init_val     # for first block of message previous hash is initial value"""
                f_out = sha_func(last_Hash, SHA_MSG[i*1024 : (i+1)*1024])  # calling F with 2 values
                last_Hash = X_OR(f_out, last_Hash)    # new hash is XOR of out put of F and previous hash
            # 5th phase od SHA-512 algorithm :
            return last_Hash

def HMAC_SHA512(key, message):
    # PREPROCESSING : coverting to binary
    key = ''.join(format(ord(x), 'b') for x in key)    # converting string to binary for key
    message = ''.join(format(ord(y), 'b') for y in message)  # converting string to binary for message
    # SETTING THE HMAC PARAMETERS:
    b = 512   # the message is made by L blocks of 64 bytes  -- each block : 512 bit = 64 byte
    k_plus = ""
    # length of k+  must be eqal to b bits:
    if len(key) == b :
        k_plus = key
    elif len(key) > b :
        k_plus = key[0: b]
    elif len(key) < b :
        padding = '0'*(b - len(key))
        k_plus = padding + key
    hex_36 = "00110110"
    hex_5C = "01011100"
    # length of hex_36 is equal to  length of hex_5C
    ipad = ""
    opad = ""
    # length of ipad and opad  must be eqal to b bits:
    if len(hex_36) == b :
        ipad = hex_36
        opad = hex_5C
    elif len(hex_36) > b :
        ipad = hex_36[0: b]
        opad = hex_5C[0: b]
    elif len(hex_36) < b :       # iteration of ipad & opad  -- till b bits:
        for i in range(b):
            ipad += hex_36[i % len(hex_36)]
            opad += hex_5C[i % len(hex_5C)]

    Si = X_OR(k_plus, ipad)
    S0 = X_OR(k_plus, opad)
    # HAMAC ALGORITHM :
    msg1 = Si + message
    H_msg1 = SHA_512(msg1)        # H(Si || M)
    H_msg1_pad = H_msg1     # By default
    if len(H_msg1) < b :
        pad = "0" * (b-len(H_msg1))
        H_msg1_pad = pad + H_msg1    # padding for out put of the first hashing (if necessary)
    msg2 = S0 + H_msg1_pad
    Hmac_outPut = SHA_512(msg2)    # HMAC(K,M) = H_SHA512[K+ XOR opad) || H_SHA512[K+ XOR ipad)|| M]]
    return  Hmac_outPut

def chunkstring(string, length):        # splitting the binary hash string into fixed length chunks
    return (string[0+i:length+i] for i in range(0, len(string), length))


if __name__== "__main__":
    message = input("Enter your message : ")
    key = input(" Enter your key : ")
    print(" _________________________________________________ HASH ALGORITHM : HAMC_SHA512 _____________________"
          "_______________________________")
    print("                                         The Hash value of your (message,key) in binary form : ")
    Hash_value = HMAC_SHA512(key, message)
    print(Hash_value)
    print("                                       The Hash value of your (message,key) in Hexadecimal form : ")
    temp = list(chunkstring(Hash_value, 4))    # splitting the binary hash string into fixed length chunks --
    # chunk size == 4 bit
    for i in range(len(temp)):
        temp[i] = hex(int(temp[i], 2))[2: ]     # converting (4 bits) binary to hexadecimal
    Hash_hex = ""
    Hash_hex = ''.join(str(x) for x in temp)   # hashed value in hexadecimal form -- String
    print(Hash_hex)
    print("___________________________________________________ Hashing Done Successfully! _______________________"
          "_______________________________")


