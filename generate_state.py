import json
import random

def generate_username():
    user="user_"

    for _ in range(5):
        user+=random.choice("abcdefghijklmnopqrstuvwxyz_")
        user+=random.choice("0123456789")
    
    return user

def generate_password(i):

    password=""
    for _ in range(5):
        password+=random.choice("abcdefghijklmnopqrstuvwxyz")
        password+=random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        password+=random.choice("1234567890")
        password+=random.choice("!@#$%^&*-=_+")
    if i%500==0:
        length=random.choice([7,8,8,8,8,8,8,9,12,10,15,18,19,21])
    else:
        length=random.choice([8,8,8,8,8,8,9,12,10,15])

    password=password[:length]
    
    return password

def generate_user_data(i):
    if i%100==0:
        mfa=random.choice([True, False, None])
        devices=random.choice(range(0,5))
        fails=random.choice(range(0, 9))
        session=random.choice(range(0,59))
    
    else:
        mfa=True
        devices=random.choice(range(0,3))
        fails=random.choice(range(0, 6))
        session=random.choice(range(0,31))

    return mfa, devices, fails, session

def assemble_record(id, pwd, mfa, dvs, fails, ssn):
    record={
        "username": id,
        "password": pwd,
        "mfa": mfa,
        "devices": dvs,
        "failed_attempts": fails,
        "idle_minutes": ssn
    }

    return record

def main():
    records=[]

    for i in range(100000):
        id=generate_username()
        pwd=generate_password(i)
        mfa, dvs, fails, ssn=generate_user_data(i)

        record=assemble_record(id, pwd, mfa, dvs, fails, ssn)
        records.append(record)
    
    data={"users": records}
    with open("system_state.json", "w") as f:
        json.dump(data, f, indent=2)

main()
