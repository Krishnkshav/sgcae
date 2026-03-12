import re
import sys
import json
import uuid
import ijson
import random
from datetime import datetime as dt
from pytz import timezone as tz



# ================================================================
# CORE COMMAND AND EXECUTION OF SECURITY GOVERNANCE AND COMPLIANCE
# ================================================================

class Execution:

    @staticmethod
    def execute_policy_check(file: str)->dict[str, dict]:
        print("\n")
        print("[+] Stage I execution begins")

        # =================== Priliminary check ===================
        if not file or not isinstance(file, str):
            print("[-] Stage I execution interrupted")
            sys.exit("[?] Unknown File Error")
        
        try:
            policies=read_policies(file)
            if not policies:
                raise ValueError
            print("[+] Stage I execution completed")
            return policies
        
        except (ValueError):
            print("[-] Stage I execution interrupted")
            sys.exit("[?] Unknown File Error")
    
        
    @staticmethod
    def execute_records_check_and_validation(file: str, policies: dict)->tuple[set, dict[str, list[int]]]:
        print("\n")
        print("[+] Stage II execution begins")

        if (
            not policies or
            not file or
            not isinstance(file, str) or
            not isinstance(policies, dict)
        ):
            print("[-] Stage II execution interrupted")
            sys.exit("[?] Unknown File Error")
        
        try:
            records=read_records(file, policies)
            set_of_valids, dict_of_violations=records

            if not set_of_valids and not dict_of_violations:
                raise ValueError
            
            print("[+] Stage II execution completed")
            return records
        
        except (ValueError):
            print("[-] Stage II execution interrupted")
            sys.exit("[?] Unknown File Error")
    

    @staticmethod
    def execute_governance_and_compliance(valid_records: set, invalid_records: dict)->bool:
        print("\n")
        print("[+] Stage III execution begins")

        if not isinstance(valid_records, set):
            print("[-] Stage III execution interrupted")
            sys.exit("[?] Unknown File Error")
        
        if not isinstance(invalid_records, dict):
            print("[-] Stage III execution interrupted")
            sys.exit("[?] Unknown File Error")
            
        # =================== Terminal display ===================
        user_policy_violations=set()
        password_policy_violations=set()
        login_policy_violations=set()
        mfa_policy_violations=set()
        session_policy_violations=set()

        positions={
            "username": 0,
            "password": 1,
            "login": 2,
            "mfa": 3,
            "session": 4
        }

        for record, valid in invalid_records.items():
            if valid[positions["username"]]==0:
                user_policy_violations.add(record)

            if valid[positions["password"]]==0:
                password_policy_violations.add(record)

            if valid[positions["login"]]==0:
                login_policy_violations.add(record)

            if valid[positions["mfa"]]==0:
                mfa_policy_violations.add(record)

            if valid[positions["session"]]==0:
                session_policy_violations.add(record)
                
        results=(user_policy_violations, password_policy_violations, login_policy_violations, mfa_policy_violations, session_policy_violations)

        publish_terminal_results(valid_records, len(invalid_records), results)

        logged=log_evidence(valid_records, invalid_records)
        if logged:
            print("[+] Stage III execution completed")
            return True
        else:
            print("[-] Stage III execution interrupted")
            return False
    


# =======================================================
# LOG VALIDATION -> POLICY ALIGNMENT -> BINARY CONVERSION
# =======================================================

class Validate:
    def __init__(self):
        self.records=None

    # =================== Primary and Secondary checks -> Main validation ===================
    # =======================================================================================
    def read_and_validate(self, policies: dict, user: dict)->tuple[bool, list[int]]:

        if not isinstance(policies, dict):
            print("[-] Stage II execution interrupted")
            sys.exit("[?] Unknown file error")
        
        checks=["username", "password", "mfa", "devices", "failed_attempts","idle_minutes"]

        # =================== Primary parameters check ===================
        if not all([parameter in user for parameter in checks]):
            print(f"[-] Stage II execution interrupted")
            raise ValueError
        
        # =================== Secondary parameters check ===================
        validation_types = {
        "username": str,
        "password": str,
        "mfa": (bool, type(None)),
        "devices": int,
        "failed_attempts": int,
        "idle_minutes": (int, float)
        }

        for param, value in user.items():
            if not param in validation_types:
                print(f"[-] Stage II execution interrupted")
                return False, []
            
            if not isinstance(value, validation_types[param]):
                print(f"[-] Stage II execution interrupted")
                return False, []
        
        # =================== Main validation ===================
        is_valid, binary_result=self.validate(user, policies)
        return is_valid, binary_result

    
    # =================== Validation -> Policy alignment -> Binary conversion ===================
    # ===========================================================================================
    def validate(self, user: dict, policies: dict)->tuple[bool, list[int]]:

        if not isinstance(user, dict) or not isinstance(policies, dict):
            print(f"[-] Stage II execution interrupted")
            return False, []
        
        uc, pc, lc, mfa_c, sc = 0, 0, 0, 0, 0
        # =================== Username Check ===================
        username=user["username"]
        username_policy=policies["username_policy"]

        if all([len(username)>=username_policy["min_length"], len(username)<=username_policy["max_length"]]):
            uc+=1
        if username_policy["uppercase"] is None:
            uc+=1
        elif (username_policy["uppercase"] and any(char.isupper() for char in username)):
            uc+=1
        elif username_policy["uppercase"] is False and not any(char.isupper() for char in username):
            uc+=1
        if username_policy["numbers"] is None:
            uc+=1
        elif (username_policy["numbers"] and any(char.isdigit() for char in username)):
            uc+=1
        elif username_policy["numbers"] is False and not any(char.isdigit() for char in username):
            uc+=1
        if username_policy["underscore"] is None:
            uc+=1
        elif username_policy["underscore"] and "_" in username:
            uc+=1
        elif username_policy["underscore"] is False and not "_" in username:
            uc+=1
        if username_policy["symbols"] is None:
            uc+=1
        elif (username_policy["symbols"] and any(not char.isalnum() and char!="_" for char in username)):
            uc+=1
        elif username_policy["symbols"] is False and not any(not char.isalnum() and char!="_" for char in username):
            uc+=1

        # =================== Password Check ===================
        password=user["password"]
        password_policy=policies["password_policy"]

        if all([len(password)>=password_policy["min_length"], len(password)<=password_policy["max_length"]]):
            pc+=1
        if password_policy["uppercase"] is None:
            pc+=1
        elif (password_policy["uppercase"] and any(char.isupper() for char in password)):
            pc+=1
        elif password_policy["uppercase"] is False and not any(char.isupper() for char in password):
            pc+=1
        if password_policy["numbers"] is None:
            pc+=1
        elif (password_policy["numbers"] and any(char.isdigit() for char in password)):
            pc+=1
        elif password_policy["numbers"] is False and not any(char.isdigit() for char in password):
            pc+=1
        if password_policy["symbols"] is None:
            pc+=1
        elif (password_policy["symbols"] and any(not char.isalnum() for char in password)):
            pc+=1
        elif password_policy["symbols"] is False and not any(not char.isalnum() for char in password):
            pc+=1

        # =================== Login Check ===================
        failed_attempts=user["failed_attempts"]
        login_fails=policies["login_policy"]["max_failed_attempts"]

        total_devices=user["devices"]
        maximum_devices=policies["login_policy"]["max_devices"]

        if failed_attempts<=login_fails:
            lc+=1
        
        if total_devices<=maximum_devices:
            lc+=1
        
        # =================== Multi-Factor Authentication Check ===================
        mfa=user["mfa"]
        access_policy=policies["access_policy"]

        if access_policy["mfa_required"] is None:
            mfa_c+=1

        elif (access_policy["mfa_required"] and mfa):
            mfa_c+=1

        elif access_policy["mfa_required"] is False and not mfa:
            mfa_c+=1
    
        
        # =================== Session Check ===================
        idle_minutes=user["idle_minutes"]
        session_policy=policies["session_policy"]

        if idle_minutes<=session_policy["max_idle_minutes"]:
            sc+=1
        
        # =================== Finalization ===================
        parameters=(uc, pc, lc, mfa_c, sc)
        is_valid, results=self.declare_result(parameters)
        return is_valid, results
        
        
    # =================== Result declaration -> Binary conversion -> Final validation ===================
    # ===================================================================================================
    def declare_result(self, check: tuple)->tuple[bool, list[int]]:
        if not check or not isinstance(check, tuple) or len(check)!=5:
            print(f"[-] Stage II execution interrupted")
            return False, []

        check1, check2, check3, check4, check5 = check
        
        if not all([
            isinstance(check1, int),
            isinstance(check2, int),
            isinstance(check3, int),
            isinstance(check4, int),
            isinstance(check5, int)
        ]):
            print(f"[-] Stage II execution interrupted")
            return False, []
        
        # =================== Policy parameters check ===================
        param_check={
            "username_check": 5,
            "password_check": 4,
            "login_check": 2,
            "mfa_check": 1,
            "session_check": 1
        }

        value_check=[check1, check2, check3, check4, check5]
        declaration=False
        binary_result=[]

        # =================== Binary conversion and final validation ===================
        parameters=list(param_check.keys())
        for i in range(len(value_check)):
            if value_check[i]==param_check[parameters[i]]:
                binary_result.append(1)
            else:
                binary_result.append(0)
        
        if all([i==1 for i in binary_result]):
            declaration=True
        
        return declaration, binary_result



# ========================================
# PROFILE GENERATION -> AUDIT ID ALLOTMENT
# ========================================

class GenerateEvidence:
    def __init__(self):
        self.records=None
    
    profile={
            0: "Username Policy",
            1: "Password Policy",
            2: "Login Policy",
            3: "MFA Policy",
            4: "Session Policy"
        }
    
    def generate_audit_report(self, violations: dict)->bool:
        if not isinstance(violations, dict):
            return False
        
        # =================== Report generation and Audit ID allotment ===================
        try:
            with open("governance_audit_report.txt", "w") as f:
                f.write("TITLE: GOVERNANCE AUDIT REPORT\n")
                f.write("======================================================\n\n")
                audit_id=str(uuid.uuid4())
                f.write(f"Governance Audit ID: {audit_id}\n")
                current=dt.now(tz("Asia/Kolkata"))
                f.write(f"{current.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"{len(violations)} users observed with policy violations:\n\n")
                f.write("======================================================\n\n")
                user_id=1000000
                # =================== Governance per user ====================
                for user, reports in violations.items():
                    f.write(f"[-] User: {user}\n")
                    user_id+=1
                    f.write(f"Audit ID: {user_id}/{audit_id}\n")
                    risk_score=0
                    for i in range(len(reports)):
                        f.write(f"    - {self.profile[i]}: ")
                        if reports[i]==0:
                            f.write("FAIL\n")
                            risk_score+=10
                        else:
                            f.write("PASS\n")
                    f.write("\n")
                    f.write(f"Risk Score: {risk_score}\n")
                    f.write("Governance Status: ")
                    if risk_score<0:
                        f.write("ERROR\n") 
                    elif risk_score==0:
                        f.write("COMPLIANT\n")
                    elif 0 < risk_score < 21:
                        f.write("PARTIAL\n")
                    elif 21 <= risk_score < 31:
                        f.write("NON-COMPLIANT\n")
                    else:
                        f.write("CRITICAL\n")
                    f.write("\n=====================================================\n\n")
            return True
        except Exception:
            return False
        

    def generate_compliance_matrix(self, violations: dict)->bool:
        if  not isinstance(violations, dict):
            return False
        
        # =================== User - violation profile generation ===================
        
        compliance={}

        for user, report in violations.items():
            compliance[user]={}
            for i in range(len(report)):
                compliance[user][self.profile[i]] = "fail" if report[i]==0 else "pass"
        
        # =================== Compliance matrix generation ===================
        try:
            with open("compliance_matrix.json", "w") as f:
                json.dump(compliance, f, indent=2)
            return True
        
        except Exception:
            return False
    
    def generate_governance_evidence(self, violations: dict)->bool:
        if not isinstance(violations, dict):
            return False
        
        audit_id=random.randint(1000000, 9999999)

        try:
            with open("governance_evidence.log", "w") as f:
                for user, report in violations.items():
                    audit_id+=1
                    username=user
                    violation=0
                    for i in range(len(report)):
                        if report[i]==0:
                            violation+=1
                    score=violation*10
                    f.write(f"{audit_id} | {username} | {violation} | {score}\n")
            return True
        
        except Exception:
            return False
    
    def clean_user_record(self, users: set)->bool:
        if not isinstance(users, set):
            return False
        
        if not users:
            return True
        
        user_id=random.randint(1000000, 9999999)
        try:
            with open("clean_user_records.log", "w") as f:
                for user in users:
                    user_id+=1
                    f.write(f"{user_id} | {user}\n")
            return True
        except Exception:
            return False




# =================== Policies reading and parsing ===================
def read_policies(filename: str)->dict[str, dict]:
    if not filename or not isinstance(filename, str):
        sys.exit("[?] Unknown File Error")

    try:
        with open(filename, "r") as f:
            policies=json.load(f)

        # =================== Policy overview checks ===================
        checks = {
            "username_policy": ["min_length", "max_length", "uppercase", "numbers", "underscore", "symbols"],
            "password_policy": ["min_length", "max_length", "uppercase", "numbers", "symbols"],
            "login_policy": ["max_failed_attempts", "max_devices"],
            "access_policy": ["mfa_required"],
            "session_policy": ["max_idle_minutes"]
        }

        for section, keys in checks.items():
            if section not in policies or not all(k in policies[section] for k in keys):
                print(f"[-] Stage I execution interrupted")
                raise ValueError
        
        # =================== Policies indepth checks ===================
        validation_types = {
        "min_length": int,
        "max_length": int,
        "uppercase": (bool, type(None)),
        "numbers": (bool, type(None)),
        "underscore": (bool, type(None)),
        "symbols": (bool, type(None)),
        "max_failed_attempts": int,
        "mfa_required": (bool, type(None)),
        "max_idle_minutes": (int, float),
        "max_devices": int
        }

        for _, content in policies.items():
            for param, value in content.items():
                if param not in validation_types:
                    print(f"[-] Stage I execution interrupted")
                    raise ValueError
                
                if not isinstance(value, validation_types[param]):
                    print(f"[-] Stage I execution interrupted")
                    raise ValueError
        
        # =================== Finalization ===================
        return policies
    
    except (ValueError, FileNotFoundError, json.JSONDecodeError):
        sys.exit("[?] Unknown File Error")

    except EOFError:
        sys.exit("[!] Alert: System's Error")



def read_records(filename: str, policies: dict)->tuple[set, dict[str, list[int]]]:
    if not filename or not isinstance(filename, str):
        return set(), dict()

    valid=Validate()
    violations={}
    valids=set()

    try:
        maximum_allowed_users=1000000
        current_user_count=0
        with open(filename, "rb") as f:
            users=ijson.items(f, "users.item")
            usernames=set()
            for user in users:
                current_user_count+=1
                if current_user_count>maximum_allowed_users:
                    print("[!] Maximum allowed limit reached - System cannot proceed")
                    raise RuntimeError
                is_valid, binary_result=valid.read_and_validate(policies, user)
                if not binary_result:
                    raise ValueError
                
                username=user.get("username", None)
                count=0
                counter=10
                while username in usernames:
                    username=username+"*"
                    if count>counter:
                        raise ValueError
                    count+=1
                usernames.add(username)

                if is_valid:
                    valids.add(username)

                else:
                    violations[username]=binary_result
                    
        return valids, violations
    
    except (FileNotFoundError, ijson.JSONError, ValueError):
        print(f"[-] Stage II execution interrupted")
        print("\n\n\n")
        print("=====================================================================")
        print("[?] Any record generated by the system can be malformed or misleading")
        print("=====================================================================")
        print("\n\n\n")
        return valids, violations
    
    except RuntimeError:
        print("[?] System stopped")
        return valids, violations
    
    except EOFError:
        sys.exit("[!] Alert: System's Error")




def publish_terminal_results(valids: set, invalid_count: int, results: tuple)->None:
    if not isinstance(valids, set):
        print("[-] Stage III execution interrupted")
        sys.exit("[?] Unknown File Error")

    if not results or not isinstance(results, tuple) or len(results)!=5:
        print("[-] Stage III execution interrupted")
        sys.exit("[?] Unknown File Error")
    
    user_policy_violations, password_policy_violations, login_policy_violations, mfa_policy_violations, session_policy_violations = results

    # =================== Terminal display of results ===================
    print("\n")
    print("=================== Terminal display of results ===================")
    print("===================================================================\n")
    print("[+] Summary: ")
    print(f"    [+] Users with no violations: {len(valids)}")
    print(f"    [+] Users with violations: {invalid_count}")
    print(f"    [+] Total users observed: {len(valids) + invalid_count}")
    print("\n")
    print("\n\n")
    print("===========================================================\n")
    print("\n")
    # ------------------- Valid users observation ------------------
    if len(valids)==0:
        print("[!] SYSTEM ALERT:")
        print("[-] No valid user observed")
        print("[-] Either the records are malformed or corrupted")
        print("[-] !! IMMEDIATE ACTION IS REQUIRED !!")
        print("===========================================================\n")
    
    else:
        print(f"[+] Total {len(valids)} valid users observed")

    # ------------------- User Policy Violations ------------------
    if len(user_policy_violations)==0:
        print("[+] No Username Policy Violations")
    else:
        print(f"[-] Total {len(user_policy_violations)} username policy violations observed")
    
    # ------------------- Password Policy Violations ------------------
    if len(password_policy_violations)==0:
        print("[+] No Password Policy Violations")
    else:
        print(f"[-] Total {len(password_policy_violations)} password policy violations observed")

    # ------------------- Login Policy Violations ------------------
    if len(login_policy_violations)==0:
        print("[+] No Login Policy Violations")
    else:
        print(f"[-] Total {len(login_policy_violations)} login policy violations observed")

    # ------------------- MFA Policy Violations ------------------
    if len(mfa_policy_violations)==0:
        print("[+] No MFA Policy Violations")
    else:
        print(f"[-] Total {len(mfa_policy_violations)} mfa/access policy violations observed")

    # ------------------- Session Policy Violations ------------------
    if len(session_policy_violations)==0:
        print("[+] No Session Policy Violations")
    else:
        print(f"[-] Total {len(session_policy_violations)} session policy violations observed")
    
    print("\n")


def log_evidence(valids: set, invalids: dict)->bool:
    if not isinstance(valids, set):
        return False
    if not isinstance(invalids, dict):
        return False
    
    evidence=GenerateEvidence()
    ar_status=evidence.generate_audit_report(invalids)
    cm_status=evidence.generate_compliance_matrix(invalids)
    ge_status=evidence.generate_governance_evidence(invalids)
    cu_status=evidence.clean_user_record(valids)

    return any([ar_status, cm_status, ge_status, cu_status])
    
    

def main():
    if len(sys.argv)!=3:
        sys.exit("[!] Invalid Command")
    
    policies=sys.argv[1]
    users=sys.argv[2]

    file_pattern=r"^[A-Za-z0-9_]+\.json$"

    if not (
        re.fullmatch(file_pattern, policies) and
        re.fullmatch(file_pattern, users)
    ):
        sys.exit("[!] Invalid Files")
    
    print("\n")
    print("[+] WELCOME TO SECURITY GOVERNANCE AND COMPLIANCE")
    print("[+] THE CORE COMMAND IS BEGINNING\n")

    execute=Execution()

    rules=execute.execute_policy_check(policies)

    valid_records, invalid_records=execute.execute_records_check_and_validation(users, rules)

    execution_complete=execute.execute_governance_and_compliance(valid_records, invalid_records)

    if execution_complete:
        print("\n[+] SECURITY GOVERNANCE AND COMPLIANCE EXECUTED SUCCESSFULLY\n\n")
    else:
        print("\n[-] SECURITY GOVERNANCE AND COMPLIANCE EXECUTION INTERRUPTED\n\n")


if __name__=="__main__":
    main()