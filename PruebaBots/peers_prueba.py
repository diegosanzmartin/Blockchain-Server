import requests, string, random, time

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def login():
    username = get_random_string(6)
    pload = {"username": username}
    peers.append(username)
    requests.post(url + "login", data=pload)
    print("->new user:", username)

def mine():
    miner = peers[random.randint(0, len(peers)-1)]
    pload = {"miner": miner}
    requests.post(url + "mine", data= {"miner": pload})
    print("->%s is mining" % miner)

def new_transaction():
    pload = {"input1": peers[random.randint(0, len(peers)-1)], "input2": random.randint(0, len(peers)-1), "sender": peers[random.randint(0, len(peers)-1)]}
    print("->new transaction:", pload)
    requests.post(url + "new_transaction", data=pload)

peers = []

if __name__ == '__main__':
    url = input("Introduzca una url: ")

    login()
    login()

    while True:
        time.sleep(random.randint(0, 3))
        opt = random.randint(0, 3)

        if opt == 0:
            login()
        elif opt == 1:
            new_transaction()
        else:
            mine()