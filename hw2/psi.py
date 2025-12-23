from multiprocessing import Pipe, Process
from elgamal.elgamal import Elgamal, PublicKey, CipherText
from random import getrandbits

# Basic configuration
key_length = 32
item_bit_length = 5
mask_bit_length = 6
num_item = 8
mask_byte_length = (mask_bit_length + 7) // 8

# -------------------------------------------
# Alice's process
# -------------------------------------------
def Alice(end_a):
    item_set = [28, 15, 7, 3, 23, 20, 31, 19]
    intersection = set()

    for item in item_set:
        for i in range(num_item):
            alice_overall_mask = 0
            for j in range(item_bit_length):
                bit = (item >> j) & 1
                pk, sk = Elgamal.newkeys(key_length)
                rand_y = getrandbits(pk.p.bit_length()) % pk.p
                pk_rand = PublicKey(pk.p, pk.g, rand_y)

                # Send both keys to Bob (order depends on bit value)
                if bit == 0:
                    msg = {'i': i, 'j': j, 'pk_0': pk, 'pk_1': pk_rand}
                else:
                    msg = {'i': i, 'j': j, 'pk_0': pk_rand, 'pk_1': pk}
                end_a.send(msg)

                # Receive Bob’s encrypted masks
                msg = end_a.recv()
                c0, c1 = msg['c0'], msg['c1']

                # Decrypt correct ciphertext based on bit
                decrypted_bytes = Elgamal.decrypt(c0, sk) if bit == 0 else Elgamal.decrypt(c1, sk)
                decrypted_mask = int.from_bytes(decrypted_bytes, 'big')
                alice_overall_mask ^= decrypted_mask

                # Compare masks at the last bit
                if j == item_bit_length - 1:
                    msg = end_a.recv()
                    bob_overall_mask = msg['bob_mask']
                    if alice_overall_mask == bob_overall_mask:
                        intersection.add(item)

    # Notify Bob the protocol is done
    end_a.send('done!')
    print("Bob's set: [14, 23, 2, 24, 7, 5, 17, 20]")
    print("Alice's set:", item_set)
    print("Alice and Bob's intersection is:", intersection)

# -------------------------------------------
# Bob's process
# -------------------------------------------
def Bob(end_b):
    item_set = [14, 23, 2, 24, 7, 5, 17, 20]

    while True:
        msg = end_b.recv()
        if msg == 'done!':
            break

        i, j = msg['i'], msg['j']
        pk_0, pk_1 = msg['pk_0'], msg['pk_1']

        bob_item = item_set[i]
        bob_bit = (bob_item >> j) & 1

        if j == 0:
            bob_overall_mask = 0

        mask_0 = getrandbits(mask_bit_length)
        mask_1 = getrandbits(mask_bit_length)

        # Update Bob’s mask based on his bit
        bob_overall_mask ^= mask_0 if bob_bit == 0 else mask_1

        # Encrypt and send both masks
        c0 = Elgamal.encrypt(mask_0.to_bytes(mask_byte_length, 'big'), pk_0)
        c1 = Elgamal.encrypt(mask_1.to_bytes(mask_byte_length, 'big'), pk_1)
        end_b.send({'c0': c0, 'c1': c1})

        # Send mask at last bit
        if j == item_bit_length - 1:
            end_b.send({'bob_mask': bob_overall_mask})

# -------------------------------------------
# Main execution
# -------------------------------------------
if __name__ == "__main__":
    end_a, end_b = Pipe()
    alice_p = Process(target=Alice, args=(end_a,))
    alice_p.start()
    Bob(end_b)
    alice_p.join()
