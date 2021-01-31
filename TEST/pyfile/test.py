import subprocess
import os
import re
import shutil

sol_path="../solfile"
sfuzzdir_path="../sfuzzdir"
oyente_path="../../oyente/oyente"
oyente_output_file_path="./oyenteoutput.csv"
oyente_log_file_path="./oyentelog.txt"
sfuzz_path="../../sFuzz/build/fuzzer"
sfuzz_output_file_path="./sfuzzoutput.csv"
sfuzz_log_file_path="./sfuzzlog.txt"

sfuzz_test_time = 120
sfuzz_bug_list = ['gasless send', 'exception disorder', 'reentrancy', 'timestamp dependency',
              'block number dependency', 'dangerous delegatecall', 'freezing ether',
              'integer overflow', 'integer underflow']

def copy_dir(src_dir_path, dest_dir_path):
    if os.path.exists(dest_dir_path):
        shutil.rmtree(dest_dir_path)
    shutil.copytree(src_dir_path, dest_dir_path)

def make_dir(dir_path):
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    os.mkdir(dir_path)

def oyente_generate(sol_path,exec_path,output_file_path,log_file_path):
    # oyente
    out=open(output_file_path,"w")
    log=open(log_file_path,"w")
    out.write("filename, err code, Integer Underflow, Integer Overflow, Parity Multisig Bug 2, Callstack Depth Attack Vulnerability, Transaction-Ordering Dependence (TOD), Timestamp Dependency, Re-Entrancy Vulnerability, \n")
    files = os.listdir(sol_path)
    for filename in files:
        if filename[-3:]=='sol': # end with".sol"
            versiontest=open(f"{sol_path}/{filename}","r")
            content=versiontest.read()
            getversion=re.search("pragma solidity \^([\.0-9]*);\n",content)
            if getversion:
                solversion=getversion.group(1)
                subprocess.getstatusoutput(f"solc use {solversion}")
            else:
                subprocess.getstatusoutput(f"solc use 0.4.19")

            k=subprocess.getstatusoutput(f"python2.7 {exec_path}/oyente.py -s {sol_path}/{filename} -ce")
            out.write(f"{filename}, {k[0]}, ")

            pattern="INFO:symExec:( |\t)*(.*):( |\t)*(True|False)"
            matches=re.finditer(pattern, k[1], flags=0)
            bugs = [(match.group(2),match.group(4)) for match in matches]
            for bug in bugs:
                out.write(f"{bug[1]}, ")
            
            out.write("\n")
            print(f"scan {filename}, return {k[0]}")
            log.write((f"scan {filename}, return {k[0]}\n"))
            if(int(k[0]==1)):
                log.write(f"=================\nlog:\n{k[1]}\n=================\n\n")
    out.close()
    log.close()

def mk_datdir(sol_path,sfuzzdir_path):
    #copy file to sfuzzdir
    dirs = os.listdir("./")
    for solname in dirs:
        if os.path.isdir(f"./{solname}"):
            a=open(f"./{solname}/testcaseCount.dat","rb")
            if(a):
                p=a.read(1)
                a.close()
                if(p!=bytes([0])):
                    copy_dir(f"./{solname}",f"{sfuzzdir_path}/{solname}")
                    shutil.copyfile(f"{sol_path}/{solname}.sol",f"{sfuzzdir_path}/{solname}/{solname}.sol")
                    print(solname)
            shutil.rmtree(f"./{solname}")

def sfuzz_test(sol_dir_path, exec_path, output_path,test_time,bug_list):
    subprocess.getstatusoutput(f"solc use 0.4.24")
    result_file=open(output_path,"w")
    result_file.write('contract name, Run Time, Coverage, ')
    for bugname in bug_list:
        result_file.write(f"{bugname}, ")
    result_file.write("Not Tested, \n")

    dirs = os.listdir(sol_dir_path)
    if not dirs:
        print('No file!')
        return

    sfuzz_sol_dir_path = f"{exec_path}/contracts/"
    pyfile_path=os.getcwd()
    for sol_name in dirs:
        os.chdir(pyfile_path)
        make_dir(sfuzz_sol_dir_path)
        copy_dir(f"{sol_dir_path}/{sol_name}",sfuzz_sol_dir_path)
        os.chdir(exec_path)
        print('Start fuzzing ' + sol_name)

        result_file.write(f"{sol_name}, ")
        print(sol_name, end=': ')
        is_tested = True
        try:
            subprocess.getstatusoutput(f'./fuzzer -g -r 0 -d {test_time} && chmod +x ./fuzzMe')
            test_info = subprocess.getstatusoutput(f'./fuzzMe')
        except:
            is_tested = False
        else:
            runtime_info = re.findall(r' run time : (\d+) days, (\d+) hrs, (\d+) min, (\d+) sec', test_info[1])
            if runtime_info:
                runtime = runtime_info[-1][0] + 'd ' + runtime_info[-1][1] + 'h ' + runtime_info[-1][2] + 'm ' \
                        + runtime_info[-1][3] + 's'
                result_file.write(f"{runtime}, ")
                print(runtime, end='  ')

                coverage_info = re.findall(r'coverage : (\d+%)', test_info[1])[-1]
                result_file.write(f"{coverage_info}, ")
                print(f'cover:{coverage_info}')

                for bug in bug_list:
                    info = re.search(f'{bug} : found', test_info[1])
                    result_file.write(f"{bool(info)}, ")
                    print(f'{bug}:{bool(info)}', end=' ')
            else:
                is_tested = False

        result_file.write(f"{is_tested}, \n")
        if not is_tested:
            print('Not tested', end='')
        print('\n')
    
    result_file.close()

if __name__ == '__main__':
    #oyente_generate(sol_path,oyente_path,oyente_output_file_path,oyente_log_file_path)
    #mk_datdir(sol_path,sfuzzdir_path)
    sfuzz_test(sfuzzdir_path,sfuzz_path,sfuzz_output_file_path,sfuzz_test_time,sfuzz_bug_list)