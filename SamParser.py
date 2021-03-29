from collections import OrderedDict
from Registry import Registry
import struct, argparse
from datetime import datetime



BASE_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
ACCOUNTS_PATH = "SAM\\Domains\\Account\\Users"
GROUPS_PATH = "SAM\\Domains\\Builtin\\Aliases"

def filetime2datetime(filetime):
    if filetime:
        dt = (datetime.utcfromtimestamp((filetime - BASE_FILETIME)/HUNDREDS_OF_NANOSECONDS)).strftime('%d %B %Y - %H:%M:%S')
    else:
        dt = 'Never'

    return(dt)





def parse_accounts(accounts_root):

    users_f = {}
    users = []
    user = {}
    for key in accounts_root.subkeys():
        if key.name() == "Name":
            continue
        else:
            for val in key.values():

                #The F value in each users subkey contains login info
                user["KeyName"] = key.name()
                if val.name() == "F":
                    user["Last logon"] = filetime2datetime(struct.unpack("<q", val.value()[8:16])[0])  # Last logon - stored NT time format, nulls if never logged on
                    user["Password last set"] = filetime2datetime(struct.unpack("<q", val.value()[24:32])[0] )        # Password last set - stored NT time format, nulls if not changed
                    user["Account expires"] = filetime2datetime(struct.unpack("<q", val.value()[40:48])[0])  # Account expires - stored NT time format, nulls if set not to expire
                    user["RID"] = struct.unpack("<L", val.value()[48:52])[0]                                # RID User Number - stored in reverse hex?
                    user["flags?"] = struct.unpack("<H", val.value()[56:58])[0]                                 # flags
                    user["Failed Login Count"] = struct.unpack("<H", val.value()[64:66])[0]                 # Failed Login Count
                    user["Login Count"] = struct.unpack("<H", val.value()[66:68])[0]                            # Login Count


                if val.name() == "V":
                    #The V value store some additional info about the users, and its password hash (LM and/or NTLM)
                    account_type = struct.unpack("<L", val.value()[4:8])[0]
                    username_offset = struct.unpack("<L", val.value()[12:16])[0]+0xCC
                    username_len = struct.unpack("<L", val.value()[16:20])[0]
                    user["username"] = (val.value()[username_offset:username_offset+username_len]).decode('utf-8').replace("\x00",'')
                    fullname_ofset = struct.unpack("<L", val.value()[24:28])[0] + 0xCC
                    fullname_len = struct.unpack("<L", val.value()[28:32])[0]
                    user["fullname"] = (val.value()[fullname_ofset:fullname_ofset+fullname_len]).decode('utf-8').replace("\x00",'')
                    comment_offset = struct.unpack("<L", val.value()[36:40])[0] + 0xCC
                    comment_len = struct.unpack("<L", val.value()[40:44])[0]
                    user["comment"] = (val.value()[comment_offset:comment_offset+comment_len]).decode('utf-8').replace("\x00",'')
                    driveletter_offset = struct.unpack("<L", val.value()[84:88])[0] + 0xCC
                    driveletter_len = struct.unpack("<L", val.value()[88:92])[0]
                    user["driveletter"] = (val.value()[driveletter_offset:driveletter_offset+driveletter_len]).decode('utf-8').replace("\x00",'')
                    logonscript_offset = struct.unpack("<L", val.value()[96:100])[0] + 0xCC
                    logonscript_len = struct.unpack("<L", val.value()[100:104])[0]
                    user["logonscript"] = (val.value()[logonscript_offset:logonscript_offset+logonscript_len]).decode('utf-8').replace("\x00",'')
                    profilepath_offset = struct.unpack("<L", val.value()[108:112])[0] + 0xCC
                    profilepath_len = struct.unpack("<L", val.value()[112:116])[0]
                    user["profilepath"] = (val.value()[profilepath_offset:profilepath_offset+profilepath_len]).decode('utf-8').replace("\x00",'')
                    workstations_offset = struct.unpack("<L", val.value()[120:124])[0] + 0xCC
                    workstations_len = struct.unpack("<L", val.value()[124:128])[0]
                    user["workstations"] = (val.value()[workstations_offset:workstations_offset+workstations_len]).decode('utf-8').replace("\x00",'')
                    lmhash_offset = struct.unpack("<L", val.value()[156:160])[0] + 0xCC
                    lmhash_len = struct.unpack("<L", val.value()[160:164])[0]
                    user["lmhash"] = val.value()[lmhash_offset:lmhash_offset+lmhash_len]
                    nthash_offset = struct.unpack("<L", val.value()[168:172])[0] + 0xCC
                    nthash_len = struct.unpack("<L", val.value()[172:176])[0]
                    user["nthash"] = val.value()[nthash_offset:nthash_offset + nthash_len]

                if "username" in user and "Last logon" in user:
                    users.append(user)
                    user = {}

    return (users)




def parse_groups(groups_root):
    groups = []

    for group_entry in groups_root.subkeys():
        group = {}
        for i in group_entry.values():
            if i.name() == "C": # offset  + 0x34
                group_name_offset = struct.unpack("<L", i.value()[16:20])[0] + 0x34
                group_name_len = struct.unpack("<L", i.value()[20:24])[0]
                group["group_name"] = (i.value()[group_name_offset:group_name_offset + group_name_len]).decode('utf-8').replace("\x00", '')
                group_comment_offset = struct.unpack("<L", i.value()[28:32])[0] + 0x34
                group_comment_len = struct.unpack("<L", i.value()[32:36])[0]
                group["group_comment"] = (i.value()[group_comment_offset:group_comment_offset + group_comment_len]).decode('utf-8').replace("\x00", '')
                num_users = struct.unpack("<L", i.value()[48:52])[0]
                group["num_users"] = num_users

                #search for users:
                users_offset = struct.unpack("<L", i.value()[40:44])[0] + 0x34
                users = []
                if num_users != 0:
                    next_entry = 0
                    counter = 0
                    while counter <= num_users-1:
                        entry = (struct.unpack("<L", i.value()[users_offset+next_entry:users_offset+next_entry+4])[0]) # each entry represents a member in the group, the first 4 bytes are header to the entry
                        if entry == 1281: # if the first 4 bytes of the entry are '\x01\x05\x00\x00'
                            user_sid_binary = i.value()[users_offset+next_entry:users_offset+next_entry + 28]
                            next_entry += 28
                            revision = struct.unpack("<B", user_sid_binary[0:1])[0] #
                            identifier_authority = int.from_bytes(user_sid_binary[2:8], byteorder='big')
                            sub_authorities = map(str, struct.unpack("<LLLL", user_sid_binary[8:24]))
                            rid = struct.unpack("<L", user_sid_binary[24:30])[0]
                            user = "S-"+str(revision)+"-"+str(identifier_authority)+"-"+'-'.join(sub_authorities)+"-"+str(rid)
                            users.append(user)
                            counter +=1

                        elif entry == 257: # if the first 4 bytes of the entry are '\x01\x01\x00\x00'
                            user_sid_binary = i.value()[users_offset+next_entry:users_offset+next_entry + 12]
                            next_entry += 12
                            revision = struct.unpack("<B", user_sid_binary[0:1])[0] #
                            identifier_authority = int.from_bytes(user_sid_binary[2:8], byteorder='big')
                            sub_authorities = struct.unpack("<L", user_sid_binary[8:12])[0]
                            user = "S-"+str(revision)+"-"+str(identifier_authority)+"-"+str(sub_authorities)
                            users.append(user)
                            counter += 1

                else:
                    users = None

            if "group_name" in group:
                group["users"] = users
                groups.append(group)

    return (groups)




def main():



    sam_hive = Registry.Registry(r"c:\sam")
    accounts_root = sam_hive.open(ACCOUNTS_PATH)
    groups_root = sam_hive.open(GROUPS_PATH)



    users = parse_accounts(accounts_root)

    groups = parse_groups(groups_root)


    print("----------------Users----------------")
    for user in users:
        print("------ UserName : {} ------".format(user["username"]))
        for key in user:
            if key != "username" and user[key] != '':
                print(key, ' : ', user[key])
        print("\n\n")

    print("----------------Groups----------------")
    for dict in groups:
        print("------ GroupName : {} ------".format(dict["group_name"]))
        for key in dict:
            if key != "group_name" and dict[key] != '':
                print(key, ' : ', dict[key])
        print("\n\n")



if __name__ == "__main__":
    main()