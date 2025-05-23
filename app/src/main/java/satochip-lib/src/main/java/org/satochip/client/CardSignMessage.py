    def card_sign_message(self, keynbr, pubkey, message, hmac=b'', altcoin=None):
        ''' Sign the message with the device
        
        Message is prepended with a specific header as described here:
        https://bitcoin.stackexchange.com/questions/77324/how-are-bitcoin-signed-messages-generated
        
        Parameters: 
        keynbr (int): the key to use (0xFF for bip32 key)
        pubkey (ECPubkey): the pubkey used for signing; this is used for key recovery
        message (str | bytes): the message to sign
        hmac: the 20-byte hmac code required if 2FA is enabled
        altcoin (str | bytes): for altcoin signing
        
        Returns: 
        (response, sw1, sw2, compsig): (list, int, int, bytes)
        compsig is the signature in  compact 65-byte format 
        (https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long)
        '''
        logger.debug("In card_sign_message")
        print("In card_sign_message")  
        
        if (type(message)==str):
            message = message.encode('utf8')
        if (type(altcoin)==str):
            altcoin = altcoin.encode('utf8')
            
        # return signature as byte array
        # data is cut into chunks, each processed in a different APDU call
        chunk= 128 # max APDU data=255 => chunk<=255-(4+2)
        buffer_offset=0
        buffer_left=len(message)

        # CIPHER_INIT - no data processed
        cla= JCconstants.CardEdge_CLA
        ins= JCconstants.INS_SIGN_MESSAGE
        p1= keynbr # 0xff=>BIP32 otherwise STD
        p2= JCconstants.OP_INIT
        lc= 0x4  if not altcoin else (0x4+0x1+len(altcoin))
        apdu=[cla, ins, p1, p2, lc]
        for i in reversed(range(4)):
            apdu+= [((buffer_left>>(8*i)) & 0xff)]
        if altcoin:
            apdu+= [len(altcoin)]
            apdu+=altcoin

        # send apdu
        (response, sw1, sw2) = self.card_transmit(apdu)

        # CIPHER PROCESS/UPDATE (optionnal)
        while buffer_left>chunk:
            #cla= JCconstants.CardEdge_CLA
            #ins= INS_COMPUTE_CRYPT
            #p1= key_nbr
            p2= JCconstants.OP_PROCESS
            lc= 2+chunk
            apdu=[cla, ins, p1, p2, lc]
            apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
            apdu+= message[buffer_offset:(buffer_offset+chunk)]
            buffer_offset+=chunk
            buffer_left-=chunk
            # send apdu
            response, sw1, sw2 = self.card_transmit(apdu)

        # CIPHER FINAL/SIGN (last chunk)
        chunk= buffer_left #following while condition, buffer_left<=chunk
        #cla= JCconstants.CardEdge_CLA
        #ins= INS_COMPUTE_CRYPT
        #p1= key_nbr
        p2= JCconstants.OP_FINALIZE
        lc= 2+chunk+ len(hmac)
        apdu=[cla, ins, p1, p2, lc]
        apdu+=[((chunk>>8) & 0xFF), (chunk & 0xFF)]
        apdu+= message[buffer_offset:(buffer_offset+chunk)]+hmac
        buffer_offset+=chunk
        buffer_left-=chunk
        # send apdu
        response, sw1, sw2 = self.card_transmit(apdu)
        
        # parse signature from response
        if (sw1!=0x90 or sw2!=0x00):
            logger.warning(f"Unexpected error in card_sign_message() (error code {hex(256*sw1+sw2)})") #debugSatochip
            compsig=b''
        else:
            # Prepend the message for signing as done inside the card!!
            hash = sha256d(msg_magic(message, altcoin))
            print(f"DEBUG: hash: {hash}")
            compsig=self.parser.parse_message_signature(response, hash, pubkey)
                
        return (response, sw1, sw2, compsig)

bfh = bytes.fromhex


def msg_magic(message: bytes) -> bytes:
    length = bfh(var_int(len(message)))
    return b"\x18Bitcoin Signed Message:\n" + length + message

def var_int(i):
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    if i<0xfd:
        return int_to_hex(i)
    elif i<=0xffff:
        return "fd"+int_to_hex(i,2)
    elif i<=0xffffffff:
        return "fe"+int_to_hex(i,4)
    else:
        return "ff"+int_to_hex(i,8)

