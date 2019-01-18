"""Secure client implementation
This is a skeleton file for you to build your secure file store client.
Fill in the methods for the class Client per the project specification.
You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError

BLOCK_SIZE = 1024
download_data = ''
class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def one_step_encrypt(self, sym_key, mac_key, msg, header, withMac=True):

        #CTR encryption
        ctr_rand = self.crypto.get_random_bytes(4)
        counter = self.crypto.new_counter(nbits = 128, initial_value = int(ctr_rand, 16))
        encrypt_msg = self.crypto.symmetric_encrypt(msg, sym_key, cipher_name='AES',mode_name='CTR', ctr=counter)

        #Creating MAC and appending it to value
        if withMac:
            mac = self.crypto.message_authentication_code(msg, mac_key, hash_name = 'SHA256')
            encrypt_msg_mac = header + encrypt_msg + "<COUNTER>" + ctr_rand + "<MAC>" + mac
        else:
            encrypt_msg_mac = header + encrypt_msg + "<COUNTER>" + ctr_rand
        return encrypt_msg_mac
    #Converts a string to a list for easy access
    def generateHeapfromString(self,heap_string, key2_mac_priv):
        ptr_list = []
        while(len(heap_string) != 0):
            ptr_index = heap_string.find("(P)")
            heap_string = heap_string[ptr_index+3:]
            next_ptr_index = heap_string.find("(P)")
            if (next_ptr_index == -1):
                ptr_list.append(self.crypto.message_authentication_code(heap_string, key2_mac_priv, hash_name='SHA256'))
                break
            ptr_list.append(self.crypto.message_authentication_code(heap_string[:next_ptr_index], key2_mac_priv, hash_name='SHA256'))
        return ptr_list

    #Insert a number, you will find pointers of the children
    def find_children_using_number(self, heap_list, parent_node_num):
        #root node number is 0; 1 returns 3, 4; 2 returns 5, 6
        #print("parent is" + heap_list[parent_node_num-1])
        return heap_list[2*(parent_node_num)], heap_list[2*(parent_node_num)+1]

    #Insert a pointer, you will find pointers of the childre
    def getChildrenFromHeap(self, parent_node_ptr, heap_list):
        #root node number is 0; 1 returns 3, 4; 2 returns 5, 6
        if heap_list.index(parent_node_ptr) == 0 :
            return heap_list[2], heap_list[3]
        parent_node_num = (heap_list.index(parent_node_ptr) - 1)
        #print("heap list is" + str(len(heap_list)))
        #print("parent is " + str(parent_node_num))
        return heap_list[2*parent_node_num], heap_list[2*parent_node_num+1]


    #Takes in a number of pointers and outputs in a string format with n pointers
    def generateHeapString(self, n):
        heap_string = ''
        while (n != 0):
            ptr = self.crypto.get_random_bytes(5)
            heap_string = heap_string + '(P)' + ptr
            n -= 1
        return heap_string
    #only input the first two variables: length & block_size
    def find_number_of_nodes(self, length, block_size):
        node_num_left = 0
        node_num_right = 0
        if (length >= 2*block_size):
            node_num_left = self.find_number_of_nodes((length/2), block_size)
            if (length%2 == 1):
                node_num_right = self.find_number_of_nodes((length/2 + 1), block_size)
            else:
                node_num_right = self.find_number_of_nodes(length/2, block_size)
        node_num = 1 + node_num_left + node_num_right
        return node_num

    def upload(self, name, value, isRevoke=False):

        #Creation of symmetric & MAC keys for use later on
        my_sym_key = str(getattr(self.elg_priv_key, 'x'))[:32]
        my_mac_key = str(getattr(self.rsa_priv_key, 'd'))[:32]

        concat = self.username + name
        uid = self.crypto.cryptographic_hash(concat, 'SHA256')
        uid, sym_key, mac_key, share_list = self.resolve(uid, my_sym_key, my_mac_key)

        val = self.storage_server.get(uid)
        #error catch here
        #resolve will return the uid of the final data node or the same uid if the data
        #doesn't exist. Thus val takes on either the actual data or none
        #if val is none we want to upload the file
        #if val is data and we are calling upload from revoke, then we want to upload the file
        #if val is data and user is calling upload, it means the user is trying to update file.

        if not val:
            val = 'k'
        if val.startswith('<DATA>') and not isRevoke: #data exists & we update
            #update the file
            #uid will be the uid of the data node
            #sym_key and mac_key are the keys of the data node
            self.update(uid, sym_key, mac_key, value)
            return

        key1_sym_pub, key1_sym = self.crypto._gen_elg_keypair(2048)
        key1_sym_priv = str(getattr(key1_sym, 'x'))[:32]
        key1_mac_pub, key1_mac = self.crypto._gen_rsa_keypair(2048)
        key1_mac_priv = str(getattr(key1_mac, 'd'))[:32]

        key2_sym_pub, key2_sym = self.crypto._gen_elg_keypair(2048)
        key2_sym_priv = str(getattr(key2_sym, 'x'))[:32]
        key2_mac_pub, key2_mac = self.crypto._gen_rsa_keypair(2048)
        key2_mac_priv = str(getattr(key2_mac, 'd'))[:32]

        #Encoding of Letterbox
        concat = self.username + name
        A_Filename = self.crypto.cryptographic_hash(concat, 'SHA256')

        #First Node
        ptr_node2 = self.crypto.get_random_bytes(64)
        node1_value = "[PTR]" + ptr_node2 + "[KEY_SYM]" + key1_sym_priv + "[KEY_MAC]" + key1_mac_priv + "[LIST]"
        node1_encrypt = self.one_step_encrypt(my_sym_key, my_mac_key, node1_value, "<PTR>")

        self.storage_server.put(A_Filename, node1_encrypt)

        #Second Node
        ptr_node3 = self.crypto.get_random_bytes(64)
        node2_value = "[PTR]" + ptr_node3 + "[KEY_SYM]" + key2_sym_priv + "[KEY_MAC]" + key2_mac_priv
        node2_encrypt = self.one_step_encrypt(key1_sym_priv, key1_mac_priv, node2_value, "<PTR>")

        self.storage_server.put(ptr_node2, node2_encrypt)

        #Third Node (Actual File)
        # we only need to change how this node works
        node3_value = value
        #node3_encrypt = self.one_step_encrypt(key2_sym_priv, key2_mac_priv, node3_value, "<DATA>")
        value_length = len(value)
        #global BLOCK_SIZE
        #BLOCK_SIZE = math.pow(value_length, (1/2))
        #self.storage_server.put(ptr_node3, node3_encrypt)
        self.merkelStore(ptr_node3, key2_sym_priv, key2_mac_priv, node3_value)

    def merkelStore(self, ptr_node3, key2_sym_priv, key2_mac_priv, node3_value):
        #create root node, root node should have header = "<DATA>" to ensure this structure
        #works with the rest of the code
        #root node consist of hash of 2 child pointers
        #a merkel leaf will be the node which contains the actual data divided into a block

        mid = int(len(node3_value)/2)
        left_child_value = node3_value[:mid]
        right_child_value = node3_value[mid:]

        hash_node3_value = self.crypto.message_authentication_code(node3_value, key2_mac_priv, hash_name='SHA256')
        if len(node3_value) <= BLOCK_SIZE:
            #print('primitively from merkelStore')
            #store the data primitely(without using tree) if it is smaller than a BLOCK_SIZE
            node3_encrypt = self.one_step_encrypt(key2_sym_priv, key2_mac_priv, node3_value, "<DATA>")
            self.storage_server.put(ptr_node3, node3_encrypt)
        else:
            numberOfNodes = self.find_number_of_nodes(len(node3_value), BLOCK_SIZE)
            #print("we have " + str(numberOfNodes) + "for " + str(len(node3_value)) + "and" + str(BLOCK_SIZE))
            heapstring = self.generateHeapString(numberOfNodes)
            heap = self.generateHeapfromString(heapstring, key2_mac_priv)
            root_value = "[HASH]" + hash_node3_value + "[FILE_LENGTH]" + str(len(node3_value)) + "[HEAP]" + heapstring
            #print ('root_value', root_value)
            node3_encrypt = self.one_step_encrypt(key2_sym_priv, key2_mac_priv, root_value, "<DATA>")
            #print (len(node3_encrypt), len(root_value) )
            self.storage_server.put(ptr_node3, node3_encrypt)
            ptr_left_child = heap[0]
            ptr_right_child = heap[1]
            self.createMerkelChild(ptr_left_child, key2_sym_priv, key2_mac_priv, left_child_value, heap)
            self.createMerkelChild(ptr_right_child, key2_sym_priv, key2_mac_priv, right_child_value, heap)

    def createMerkelLeaf(self, ptr_leaf, key2_sym_priv, key2_mac_priv, value):
        leaf_encrypt = self.one_step_encrypt(key2_sym_priv, key2_mac_priv, value, "<LEAF>")
        self.storage_server.put(ptr_leaf, leaf_encrypt)

    def createMerkelChild(self, ptr, key2_sym_priv, key2_mac_priv, value, heap):
        #recursively create the tree
        #this function takes in a pointers and creates a  nodes for it
        #it then calls itself to create the children
        mid = int(len(value)/2)
        left_child_value = value[:mid]
        right_child_value = value[mid:]
        #if len of either child value is less than BLOCK_SIZE, children are leaves
        #print('called from merkelchilderncreate', ptr)
        hash_value = self.crypto.message_authentication_code(value, key2_mac_priv, hash_name='SHA256')

        ptr_left, ptr_right = self.getChildrenFromHeap(ptr, heap)

        node_value = hash_value

        self.storage_server.put(ptr, node_value)

        if mid <= BLOCK_SIZE:

            self.createMerkelLeaf(ptr_left, key2_sym_priv, key2_mac_priv, left_child_value)
            self.createMerkelLeaf(ptr_right, key2_sym_priv, key2_mac_priv, right_child_value)
        else:

            self.createMerkelChild(ptr_left, key2_sym_priv, key2_mac_priv, left_child_value, heap)
            self.createMerkelChild(ptr_right, key2_sym_priv, key2_mac_priv, right_child_value, heap)

    def update(self, uid, sym_key, mac_key, new_value):
        #updates file stored at uid with new_value
        #get the value stored in the storage_server
        #update is always first called on the root node

        #check if new_value length is smaller than block size
        #if it is smaller, we simply upload the file primitively overwriting prev val
        if len(new_value) <= BLOCK_SIZE:
            new_value_encrypted = self.one_step_encrypt(sym_key, mac_key, new_value, '<DATA>')
            self.storage_server.put(uid, new_value_encrypted)
            return
        old_value_encrypted = self.storage_server.get(uid)

        result = self.node_decrypt(sym_key, mac_key, old_value_encrypted, 'r')
        hash_value = result['[HASH]']
        if hash_value == -1:
            #if old_value is stored primitively
            #we let merkelStore handle the update, overwriting the current file
            self.merkelStore(uid, sym_key, mac_key, new_value)
            return

        #check if the old length value equals the new lenght value,
        #if they equal perform efficient update
        length_new_value = len(new_value)
        length_old_value = int(result['[FILE_LENGTH]'])
        if length_new_value != length_old_value:
            #if length of old and new values dont match, we don't do efficient updates
            #instead we overwrite file.
            #let merkelStore handle the overwrite
            self.merkelStore(uid, sym_key, mac_key, new_value)
            return
        #check if old hash is same as new hash, if it is same, we dont need to update

        old_hash_value = self.crypto.message_authentication_code(new_value, mac_key, hash_name='SHA256')
        if old_hash_value == hash_value:
            #files are the same
            return
        #we perfrom efficient updates if all the conditions above are not satisfied
        mid = int(len(new_value)/2)
        left_child_value = new_value[:mid]
        right_child_value = new_value[mid:]

        heapstring = result['[HEAP]']
        heap = self.generateHeapfromString(heapstring, mac_key)

        pointer_left_child = heap[0]
        pointer_right_child = heap[1]
        #error catch
        value_length = len(new_value)
        #global BLOCK_SIZE
        #BLOCK_SIZE = math.pow(value_length, (1/2))
        self.efficientUpdate(pointer_left_child, sym_key, mac_key, left_child_value, heap)
        self.efficientUpdate(pointer_right_child, sym_key, mac_key, right_child_value, heap)

    def efficientUpdate(self, uid, sym_key, mac_key, new_value, heap):
        #efficientUpdate is called on child/leaf nodes only
        #if efficientUpdate is called we know that both files have same length
        #print('up', new_value)

        old_value_encrypted = self.storage_server.get(uid)
        #print('server get', len(old_value_encrypted))

        if old_value_encrypted.startswith('<LEAF>'):
            results = self.node_decrypt(sym_key, mac_key, old_value_encrypted, 'l')
            #print('leaf newval: ',new_value, ' oldval: ', results['[CONTENT]'])
            if new_value != results['[CONTENT]']:
                #if the values have changed, perform update
                new_value_encrypted = self.one_step_encrypt(sym_key, mac_key, new_value, "<LEAF>")
                self.storage_server.put(uid, new_value_encrypted)
                #print('server', len(old_value_encrypted))
            return
        elif old_value_encrypted.startswith('<CHILD>'):
            results = self.node_decrypt(sym_key, mac_key, old_value_encrypted, 'c')
            old_value_hash = results['[HASH]']

            new_value_hash = self.crypto.message_authentication_code(new_value, mac_key, hash_name='SHA256')
            if new_value_hash == old_value_hash:
                #if the hash value at current node is the same, then all descendant
                #nodes will be the same and require no updates
                return

            mid = int(len(new_value)/2)
            left_child_value = new_value[:mid]
            right_child_value = new_value[mid:]
            ptr_left_child, ptr_right_child = self.getChildrenFromHeap(uid, heap)

            #error catch
            self.efficientUpdate(ptr_left_child, sym_key, mac_key, left_child_value, heap)
            self.efficientUpdate(ptr_right_child, sym_key, mac_key, right_child_value, heap)

            #recursively update each side
    def node_decrypt(self, sym_key, mac_key, encrypted_value, header):
        #header = 'r', 'c', 'l' for root, child and leaf node respectively
        #returns a dictionary, results
        #results['[HASH]'] = hash_val this = -1 if root is primitive
        #results['[PTR_L]'] = ptr_left
        #results['[PTR_R]'] = ptr_right
        #results['[FILE_LENGTH]'] = file_length
        #results['[CONTENT]'] = CONTENT this is returned when header is leaf or when root file has been stored primitively
        #use the dictionary accordingly depending what kind of node you are decrypting

        results = {}
        if header.lower() == 'r':
            ptr_index = encrypted_value.find("<DATA>") + 6
        elif header.lower() == 'c':
            ptr_index = encrypted_value.find("<CHILD>") + 7
            results['[HASH]'] = encrypted_value[ptr_index:]
            return results
        elif header.lower() == 'l':
            ptr_index = encrypted_value.find("<LEAF>") + 6
        else:
            print ('you fucked up')
        ctr_index = encrypted_value.find("<COUNTER>")
        mac_index = encrypted_value.find("<MAC>")

        encrypt_msg = encrypted_value[ptr_index:ctr_index]
        ctr_rand = encrypted_value[ctr_index+9:mac_index]
        mac = encrypted_value[mac_index+5:]

        counter = self.crypto.new_counter(nbits = 128, initial_value = int(ctr_rand, 16))
        msg_layer_2 = self.crypto.symmetric_decrypt(encrypt_msg, sym_key, cipher_name='AES',mode_name='CTR', ctr=counter)
        msg_mac = self.crypto.message_authentication_code(msg_layer_2, mac_key, hash_name = 'SHA256')

        if (mac != msg_mac):
            raise IntegrityError


        if header.lower() == 'r':
            if msg_layer_2.startswith("[HASH]"):
                hash_index = msg_layer_2.find("[HASH]")
                file_length_index = msg_layer_2.find("[FILE_LENGTH]")
                heap_index = msg_layer_2.find("[HEAP]")

                hash_val = msg_layer_2[hash_index+6:file_length_index]
                file_length = msg_layer_2[file_length_index+13:heap_index]
                heap = msg_layer_2[heap_index+6:]

                results['[HASH]'] = hash_val
                results['[FILE_LENGTH]'] = file_length
                results['[HEAP]'] = heap
            else:
                results['[HASH]'] = -1
                results['[CONTENT]'] = msg_layer_2

        elif header.lower() == 'l':
            results['[CONTENT]'] = msg_layer_2
        else:
            print ('you fucked up')
        return results
    def resolve(self, uid, sym_key, mac_key):
        share_list = ''
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("<DATA>"):
                return uid, sym_key, mac_key, share_list
            elif res.startswith("<PTR>"):
                nextptr, next_sym_key, next_mac_key, share_list = self.pointer_decrypt(res, sym_key, mac_key)
                sym_key = next_sym_key
                mac_key = next_mac_key
                uid = nextptr
            else:
                raise IntegrityError()

    def pointer_decrypt(self, encrypt_msg_mac, sym_key, mac_key):
        #Returns pointer, sym_key and mac_key of the next node
        ptr_index = encrypt_msg_mac.find("<PTR>")
        ctr_index = encrypt_msg_mac.find("<COUNTER>")
        mac_index = encrypt_msg_mac.find("<MAC>")

        encrypt_msg = encrypt_msg_mac[ptr_index+5:ctr_index]
        ctr_rand = encrypt_msg_mac[ctr_index+9:mac_index]
        mac = encrypt_msg_mac[mac_index+5:]

        counter = self.crypto.new_counter(nbits = 128, initial_value = int(ctr_rand, 16))
        msg_layer_2 = self.crypto.symmetric_decrypt(encrypt_msg, sym_key, cipher_name='AES',mode_name='CTR', ctr=counter)
        msg_mac = self.crypto.message_authentication_code(msg_layer_2, mac_key, hash_name = 'SHA256')
        if (mac != msg_mac):
            raise IntegrityError

        msg_ptr_index = msg_layer_2.find("[PTR]")
        msg_key_sym_index = msg_layer_2.find("[KEY_SYM]")
        msg_key_mac_index = msg_layer_2.find("[KEY_MAC]")
        #For final node that has the list
        msg_list_index = msg_layer_2.find("[LIST]")

        next_ptr = msg_layer_2[msg_ptr_index+5:msg_key_sym_index]
        next_sym_key = msg_layer_2[msg_key_sym_index+9:msg_key_mac_index]

        if (msg_list_index== -1):
            next_mac_key = msg_layer_2[msg_key_mac_index+9:]
            share_list = ''
        else:
            next_mac_key = msg_layer_2[msg_key_mac_index+9:msg_list_index]
            share_list = msg_layer_2[msg_list_index+6:]

        return next_ptr, next_sym_key, next_mac_key, share_list
    def download(self, name):

        my_sym_key = str(getattr(self.elg_priv_key, 'x'))[:32]
        my_mac_key = str(getattr(self.rsa_priv_key, 'd'))[:32]

        concat = self.username + name
        uid = self.crypto.cryptographic_hash(concat, 'SHA256')
        uid, sym_key, mac_key, share_list = self.resolve(uid, my_sym_key, my_mac_key)
        #resolve will return the root node if it exist
        encrypted_value = self.storage_server.get(uid)

        #Deals with none type
        if not encrypted_value:
            return encrypted_value

        results = self.node_decrypt(sym_key, mac_key, encrypted_value, 'r')
        if results['[HASH]'] == -1:
            return results['[CONTENT]']

        #otherwise recursively get the file

        value = ''
        import queue
        pointer_queue = queue.LifoQueue()

        heapstring = results['[HEAP]']
        heap = self.generateHeapfromString(heapstring, mac_key)
        pointer_left_child = heap[0]
        pointer_right_child = heap[1]

        pointer_queue.put(pointer_right_child)
        pointer_queue.put(pointer_left_child)
        #print('left ptr', self.storage_server.get(pointer_left_child) )
        while (not pointer_queue.empty() ):
            #print('value', value)
            cur_pointer = pointer_queue.get()
            encrypted_value =  self.storage_server.get(cur_pointer)
            if (encrypted_value.startswith('<LEAF>') ):
                #print(results)
                results = self.node_decrypt(sym_key, mac_key, encrypted_value, 'l')
                value = value + results['[CONTENT]']
            elif(encrypted_value.startswith('<CHILD>')):
                results = self.node_decrypt(sym_key, mac_key, encrypted_value, 'c')
                pointer_left_child, pointer_right_child = self.getChildrenFromHeap(cur_pointer, heap)
                #print(pointer_left_child, pointer_right_child)
                pointer_queue.put(pointer_right_child)
                pointer_queue.put(pointer_left_child)
            #else:
                #print ('mess',encrypted_value)
                #print('YOU MESSED UP')
        return value


    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        #Step1: Create the node
        my_sym_key = str(getattr(self.elg_priv_key, 'x'))[:32]
        my_mac_key = str(getattr(self.rsa_priv_key, 'd'))[:32]
        sharee_key_encr = self.pks.get_encryption_key(user)


        #generate nodeAB symmetric and mac keys
        keyAB_sym_pub, keyAB_sym = self.crypto._gen_elg_keypair(2048)
        keyAB_sym_priv = str(getattr(keyAB_sym, 'x'))[:32]
        keyAB_mac_pub, keyAB_mac = self.crypto._gen_rsa_keypair(2048)
        keyAB_mac_priv = str(getattr(keyAB_mac, 'd'))[:32]

        #generate bname
        ptr_nodeAB = self.crypto.get_random_bytes(64)

        #Creation of new nodes
        concat = self.username + name
        A_Filename = self.crypto.cryptographic_hash(concat, 'SHA256')

        #find the symmetric and mac keys to node2 and the pointer to node2 by decrypting node1
        res = self.storage_server.get(A_Filename)
        ptr_node2, key1_sym_key, key1_mac_key, sharelist = self.pointer_decrypt(res, my_sym_key, my_mac_key)
        nodeAB_value = "[PTR]" + ptr_node2 + "[KEY_SYM]" + key1_sym_key + "[KEY_MAC]" + key1_mac_key

        #create nodeAB
        nodeAB_encrypt = self.one_step_encrypt(keyAB_sym_priv, keyAB_mac_priv, nodeAB_value, "<PTR>")
        self.storage_server.put(ptr_nodeAB, nodeAB_encrypt)

        #Step2: create the message
        msg = "[PTR]" + ptr_nodeAB + "[KEY_SYM]" + keyAB_sym_priv + "[KEY_MAC]" + keyAB_mac_priv

        #Assemetrically encrypt the msg using sharee's public encryption key
        encrypt_msg_assym = self.crypto.asymmetric_encrypt(msg, sharee_key_encr)

        #sign the message using your RSA key
        signature = self.crypto.asymmetric_sign(msg, self.rsa_priv_key)
        msg_prepared = '<MSG>' + encrypt_msg_assym + '<SIGN>' + signature

        #Step3: update the name list inside node 1

        #Update the sharelist
        share_list_updated = sharelist + '(USER)' + user + '(PTR)' + ptr_nodeAB + '(SYM_KEY)' + keyAB_sym_priv + "(MAC_KEY)" + keyAB_mac_priv

        #Regenerate the node1_value
        node1_value = "[PTR]" + ptr_node2 + "[KEY_SYM]" + key1_sym_key + "[KEY_MAC]" + key1_mac_key + "[LIST]" + share_list_updated

        #Encrypt the node1_value and update the server value, my_mac_key
        node1_encrypt = self.one_step_encrypt(my_sym_key, my_mac_key, node1_value, "<PTR>")
        self.storage_server.put(A_Filename, node1_encrypt)

        return msg_prepared

    def receive_share(self, from_username, newname, message):
        my_sym_key = str(getattr(self.elg_priv_key, 'x'))[:32]
        my_mac_key = str(getattr(self.rsa_priv_key, 'd'))[:32]
        sharer_rsa_pub = self.pks.get_signature_key(from_username)
        concat = self.username + newname
        B_Filename = self.crypto.cryptographic_hash(concat, 'SHA256')
        my_priv_key = self.elg_priv_key

        msg_index = message.find("<MSG>")
        sign_index = message.find("<SIGN>")

        encrypt_msg = message[msg_index+5:sign_index]
        sign = message[sign_index+6:]

        pt_msg = self.crypto.asymmetric_decrypt(encrypt_msg, my_priv_key)

        #Checks for RSA here
        if (self.crypto.asymmetric_verify(pt_msg, sign, sharer_rsa_pub) != True):
            raise IntegrityError

        #Decrypted message from A
        AB_ptr_node_index = pt_msg.find("[PTR]")
        AB_key_sym_index = pt_msg.find("[KEY_SYM]")
        AB_key_mac_index = pt_msg.find("[KEY_MAC]")

        shared_ptr = pt_msg[AB_ptr_node_index+5:AB_key_sym_index]
        AB_sym_key = pt_msg[AB_key_sym_index+9:AB_key_mac_index]
        AB_mac_key = pt_msg[AB_key_mac_index+9:]

        #First Node
        node1_value = "[PTR]" + shared_ptr + "[KEY_SYM]" + AB_sym_key + "[KEY_MAC]" + AB_mac_key
        node1_encrypt = self.one_step_encrypt(my_sym_key, my_mac_key, node1_value, "<PTR>")

        self.storage_server.put(B_Filename, node1_encrypt)

    #Converts a string to a dictionary for easy access
    def sharelist_to_list(self, share_list):
        #fixing problem with next_user_index
        share_list = share_list + ' '
        user_list = []
        while (len(share_list) != 0):
            # print("dict is now" + str(user_dict))
            user_index = share_list.find("(USER)")
            ptr_index = share_list.find("(PTR)")
            sym_key_index = share_list.find("(SYM_KEY)")
            mac_key_index = share_list.find("(MAC_KEY)")
            if (mac_key_index != -1):
                user = share_list[user_index+6:ptr_index]
                ptr = share_list[ptr_index+5:sym_key_index]
                sym_key = share_list[sym_key_index+9:mac_key_index]
                share_list = share_list[mac_key_index:]
                same_mac_key_index_appended_list = share_list.find("(MAC_KEY)")
                next_user_index = share_list.find("(USER)")
                mac_key = share_list[same_mac_key_index_appended_list+9:next_user_index]
                user_list.append((user, ptr, sym_key, mac_key))
                share_list = share_list[next_user_index:]
            else:   #last user
                share_list = ''

        # print("old dict is" + str(user_dict))
        return user_list



    def revoke(self, user, name):
        A_Filename = name
        revoked_user = user
        my_sym_key = str(getattr(self.elg_priv_key, 'x'))[:32]
        my_mac_key = str(getattr(self.rsa_priv_key, 'd'))[:32]

        #Downloads data to create new nodes
        data = self.download(A_Filename)

        #Gets old user list
        concat = self.username + name
        uid = self.crypto.cryptographic_hash(concat, 'SHA256')
        node1_data = self.storage_server.get(uid)
        nextptr, next_sym_key, next_mac_key, share_list = self.pointer_decrypt(node1_data, my_sym_key, my_mac_key)
        user_list = self.sharelist_to_list(share_list)

        self.upload(A_Filename, data, True)


        new_user_list = [user for user in user_list if (user[0] != revoked_user)]

        #Accesses node 1 of self to find address of node 2 (editing nextptr)
        concat = self.username + name
        uid = self.crypto.cryptographic_hash(concat, 'SHA256')
        node1_value = self.storage_server.get(uid)
        new_node_2_ptr, new_node_2_sym_key, new_node_2_mac_key, empty_share_list = self.pointer_decrypt(node1_value, my_sym_key, my_mac_key)
        self.changeShareeData(new_user_list, new_node_2_ptr, new_node_2_sym_key, new_node_2_mac_key)

        newUserString = self.listToString(new_user_list)
        new_node1_value = "[PTR]" + new_node_2_ptr + "[KEY_SYM]" +  new_node_2_sym_key + "[KEY_MAC]" + new_node_2_mac_key + "[LIST]" + newUserString

        #Encrypt the node1_value and update the server value, my_mac_key
        new_node1_encrypt = self.one_step_encrypt(my_sym_key, my_mac_key, new_node1_value, "<PTR>")
        self.storage_server.put(uid, new_node1_encrypt)
        #Take the new string and puts into node 1

    #for each user
    def changeShareeData(self, user_list, new_node_2_ptr, new_node_2_sym_key, new_node_2_mac_key):
        for user in user_list:
            new_sharee_node_value = "[PTR]" + new_node_2_ptr + "[KEY_SYM]" + new_node_2_sym_key + "[KEY_MAC]" + new_node_2_mac_key
            new_sharee_node_value_encrypt = self.one_step_encrypt(user[2], user[3], new_sharee_node_value, "<PTR>")
            self.storage_server.put(user[1], new_sharee_node_value_encrypt)

    def listToString(self, user_list):
        newUserString = ''
        for user in user_list:
            newUserString = newUserString + "(USER)" + user[0] + "(PTR)" + user[1] + "(SYM_KEY)" + user[2] + "(MAC_KEY)" + user[3]
        return newUserString


if __name__ == "__main__":
    from servers import PublicKeyServer, StorageServer
    from crypto import Crypto



    print("Initializing servers and clients...")
    pks = PublicKeyServer()
    server = StorageServer()
    crypto = Crypto()
    alice = Client(server, pks, crypto, "alice")
    bob = Client(server, pks, crypto, "bob")
    carol = Client(server, pks, crypto, "carol")
    dave = Client(server, pks, crypto, "dave")

    print("Testing client put and share...")
    data = 'b' * 200
    alice.upload("a", data)
    i = 5
    data = 'b' * i + 'c' + 'b' * (188) + 'c' + 'b' * i
    print (len(data))
    alice.upload("a", data)

    '''
    print(data, alice.download('a'))
    m = alice.share("bob", "a")
    bob.receive_share("alice", "q", m)
    for i in range(len(data)):
        if data != alice.download('a'):

    m = bob.share("carol", "q")
    carol.receive_share("bob", "w", m)

    m = alice.share("dave", "a")
    dave.receive_share("alice", "e", m)

    print("Testing Bob, Carol, and Dave getting their new shares...")
    print(bob.download("q"))
    assert bob.download("q") == "bcdef"
    assert carol.download("w") == "bcdef"
    assert dave.download("e") == "bcdef"

    print("Revoking Bob...")
    alice.revoke("bob", "a")
    print("dave downloads " + dave.download("e"))
    # print("bob downloads" + bob.download("q"))

    dave.upload("e", "cdefg")

    print("dave just uploaded")

    print("alice downloads " + alice.download("a"))



    print("Testing Bob, Carol, and Dave getting their shares...")
    assert alice.download("a") == "cdefg"
    assert bob.download("q") != "cdefg"
    assert carol.download("w") != "cdefg"
    assert dave.download("e") == "cdefg"
    '''
