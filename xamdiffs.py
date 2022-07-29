#!/usr/bin/env python
"""
Usage: {prog} [OPTION] FILE1 FILE2
OPTIONS
    --amdiff		Compares two AndroidManifests, ignoring element and attribute order.
    --resdiff		Requires apktool, Disassembles resources and searches for changes in them with keyword list
    --apkid     Compares results of APKiD
    --agdiff        Compares classes, methods and fields and prints changed ones
"""
import sys
import os
import io
import lxml.etree
from tempfile import NamedTemporaryFile
import subprocess
from androguard.misc import AnalyzeAPK
import androguard

NAME = '{http://schemas.android.com/apk/res/android}name'
KEYWORDLIST = ["host", "api", "token", "web"]
EXCLUDEDTYPES = ["image", "video", "media"]
new_attribs=[]
new_nodes=[]
old_attribs=[]
old_nodes=[]
changed_attribs=[]

def attr_str(k, v):
    return "{}=\"{}\"".format(k,v)

def node_str(n):
    attrs = sorted(n.attrib.items(), key=sort_attrs)
    astr = "\n".join(attr_str(k,v) for k,v in attrs)
    s = n.tag
    if astr:
        s += "\n" + astr
    return s

def sort_attrs(n):
    for k in n:
        if k == NAME:
            return ''
        else:
            return k

def node_diff(n1,n2):
    attrs1 = sorted(n1.attrib.items(), key=sort_attrs)
    attrs2 = sorted(n2.attrib.items(), key=sort_attrs)
    return set(attrs1)^set(attrs2)

def node_name(node):
    tag = node.tag
    if "permission" in node.tag or "intent" in node.tag:
        tag = '\x1b[6;31;40m' + node.tag + '\x1b[0m'
    if node.find('[@'+NAME+']') is not None:
        return tag + ":" + node.attrib[NAME]
    return tag

def write_diffed(node1, node2):
    if len(node1.attrib) < len(node2.attrib):
        new_attribs.append([node_diff(node1,node2),node_name(node1)])
    elif len(node1.attrib) > len(node2.attrib):
        old_attribs.append([node_diff(node1,node2),node_name(node1)])
    else:
        if node_diff(node1,node2):
            changed_attribs.append([node_diff(node1,node2),node_name(node1)])
    subnodes1 = list(node1)
    subnodes2 = list(node2)
    subnodes1.sort(key=node_str)
    subnodes2.sort(key=node_str)
    if subnodes1 and subnodes2:
        i = 0
        j = 0
        while i < len(subnodes1):
            while j < len(subnodes2):
                if (subnodes1[i].find('[@'+NAME+']') is not None) and (subnodes2[j].find('[@'+NAME+']') is not None):
                    if subnodes1[i].attrib[NAME] == subnodes2[j].attrib[NAME]:
                        write_diffed(subnodes1[i], subnodes2[j])
                        i += 1
                        j += 1
                    elif subnodes1[i].attrib[NAME] < subnodes2[j].attrib[NAME]:
                        old_nodes.append([subnodes1[i],node_name(node1)])
                        i += 1
                    else:
                        new_nodes.append([subnodes2[j],node_name(node2)])
                        j += 1
                elif subnodes1[i].find('[@'+NAME+']') is None and subnodes2[j].find('[@'+NAME+']') is None:
                    write_diffed(subnodes1[i], subnodes2[j])
                    i += 1
                    j += 1
    elif subnodes1 or subnodes2:
        if len(subnodes1)==0:
            for subnode2 in subnodes2:
                new_nodes.append([subnode2,node_name(node2)])
        else:
            for subnode1 in subnodes1:
                old_nodes.append([subnode1,node_name(node1)])

def danger_node(node):
    if "permission" in node.tag or "intent" in node.tag:
        node.tag = '\x1b[6;31;40m' + node.tag + '\x1b[0m'
    for attrib in node.attrib.items():
        attrib = danger_attrib(attrib)
        print(attrib)

def danger_attrib(attrib):
    if "debug" in attrib[0] or "exported" in attrib[0]:
        if attrib[1] == "true":
            return '\x1b[6;31;40m' + attrib[1] + '\x1b[0m'
        else:
            return '\x1b[6;32;40m' + attrib[1] + '\x1b[0m'
    return attrib[1]
    
def listdiffs(file1, file2):
#    write_diffed(lxml.etree.parse(file1).getroot(),lxml.etree.parse(file2).getroot())
    write_diffed(file1, file2)
    if new_attribs:
#        print("NEW ATTRIBUTES")
        for attrib in new_attribs:
            print("\nAdded attribute", list(attrib[0])[0][0], '=', danger_attrib(list(attrib[0])[0]), "in", attrib[1])
    if old_attribs:
#        print("\nOLD ATTRIBUTES")
        for attrib in old_attribs:
            print("\nDeleted attribute", list(attrib[0])[0][0], '=', danger_attrib(list(attrib[0])[0]), "in", attrib[1])
#            print(attrib[1] + ":\n", attrib[0])
    if changed_attribs:
#        print("\nCHANGED ATTRIBUTES")
        for attrib in changed_attribs:
            print("\nChanged attribute", list(attrib[0])[0][0], "from", danger_attrib(list(attrib[0])[0]), "to", danger_attrib(list(attrib[0])[1]), "in", attrib[1])
#            print(attrib[1] + ":\n", attrib[0])
    if new_nodes:
#        print("\nNEW NODES")
        for node in new_nodes:
#            print("\nAdded node")
#            print(write_nodes(node[0]) + node_name(node[0]), "in", node[1])
            print("\nAdded", node_name(node[0]), "in", node[1])
            if len(node[0].attrib) > 0:
                for attr in node[0].attrib.items():
                    if attr[1] != danger_attrib(attr):
                        print("with",attr[0],"=",danger_attrib(attr))
    if old_nodes:
#        print("\nOLD NODES")
        for node in old_nodes:
#            print("\nDeleted node")
            print("\nDeleted", node_name(node[0]), "in", node[1])
#            print(write_nodes(node[0]), "in", node[1])
#            print(node[1] + ":\n" + node[0])

def diffbykey(filename1,filename2):
    f1 = open(filename1, "r").readlines()
    f2 = open(filename2, "r").readlines()
    file_1_line = f1.readline()
    file_2_line = f2.readline()
    while file_1 != '' or file_2_line != '':
  
        # Removing whitespaces
        file_1_line = file_1_line.rstrip()
        file_2_line = file_2_line.rstrip()
  
        # Compare the lines from both file
        if file_1_line != file_2_line and any(word in line for word in KEYWORDLIST):
            # otherwise output the line on file1 and use @ sign
            if file_1_line == '':
                print("@", "Line-%d" % line_no, file_1_line)
            else:
                print("@-", "Line-%d" % line_no, file_1_line)
              
            # otherwise output the line on file2 and use # sign
            if file_2_line == '':
                print("#", "Line-%d" % line_no, file_2_line)
            else:
                print("#+", "Line-%d" % line_no, file_2_line)
  
            # Print a empty line
            print()
  
        # Read the next line from the file
        file_1_line = file_1.readline()
        file_2_line = file_2.readline()
  
        line_no += 1
    f1.close()
    f2.close()

def printwithkeyword(line):
    for word in KEYWORDLIST:
        index = line.find(word)
        if index == -1:
            continue
        line = line[:index] + '\x1b[6;31;40m' + line[index:index+len(word)] + '\x1b[0m' + line[index+len(word):]
    print(line)

def resdiff(dir1,dir2):
    import filecmp
    import difflib
    import mimetypes
    def print_diff_files(dcmp):
#        print(filecmp.cmpfiles(dcmp.left,dcmp.right,dcmp.common_files, shallow=False)[1], end=' ')
        for name in dcmp.diff_files:
            path1 = os.path.join(dcmp.left,name)
            path2 = os.path.join(dcmp.right,name)
            if all(word not in str(mimetypes.guess_type(path1)[0]) for word in EXCLUDEDTYPES):
#                if name != "AndroidManifest.xml":
                    try:
                        f1 = [s.strip() for s in open(path1, "r").readlines()]
                        f2 = [s.strip() for s in open(path2, "r").readlines()]
#                        diffbykey(path1,path2)
                        isdiffprint=0
                        for line in difflib.unified_diff(f1,f2, n=0):
                            # public.xml only initializes ids
                            if any(word in line.lower() for word in KEYWORDLIST) and name!="public.xml":
                                if isdiffprint == 0:
                                    print("\ndiff_file %s found in %s and %s" % (name, dcmp.left, dcmp.right))
                                    isdiffprint=1
                                printwithkeyword(line)
                    except UnicodeDecodeError:
                        pass
 #               else:
 #                   listdiffs(lxml.etree.parse(path1).getroot(), lxml.etree.parse(path2).getroot())
        for sub_dcmp in dcmp.subdirs.values():
            if "/tmp/apk1/smali" not in os.path.abspath(sub_dcmp.left) and "/tmp/apk1/original" not in os.path.abspath(sub_dcmp.left):
#            if "/tmp/apk1/assets" in os.path.abspath(sub_dcmp.left) or "/tmp/apk1/META-INF" in os.path.abspath(sub_dcmp.left) or "/tmp/apk1/lib" in os.path.abspath(sub_dcmp.left):
                print_diff_files(sub_dcmp)
        for name in dcmp.left_only:
            path1 = os.path.join(dcmp.left,name)
            if all(word not in str(mimetypes.guess_type(path1)[0]) for word in EXCLUDEDTYPES):
                try:
                    f1 = [s.strip() for s in open(path1, "r").readlines()]
                    isdiffprint=0
                    for line in f1:
                        if any(word in line.lower() for word in KEYWORDLIST):
                            if isdiffprint == 0:
                                print("\nold_only %s found in %s" % (name, dcmp.left))
                                isdiffprint=1
                            printwithkeyword(line)
                except UnicodeDecodeError:
                    print("\nold_only binary %s found in %s" % (name, dcmp.left))
                except IsADirectoryError:
                    print("\nold_only directory %s found in %s" % (name, dcmp.left))
        for name in dcmp.right_only:
            path2 = os.path.join(dcmp.right,name)
            if all(word not in str(mimetypes.guess_type(path2)[0]) for word in EXCLUDEDTYPES):
                try:
                    f2 = [s.strip() for s in open(path2, "r").readlines()]
                    isdiffprint=0
                    for line in f2:
                        if any(word in line.lower() for word in KEYWORDLIST):
                            if isdiffprint == 0:
                                print("\nnew_only %s found in %s" % (name, dcmp.right))
                                isdiffprint=1
                            printwithkeyword(line)
                except UnicodeDecodeError:
                    print("\nnew_only binary %s found in %s" % (name, dcmp.right))
    dcmp = filecmp.dircmp(dir1, dir2)
    print_diff_files(dcmp) 

def apkid_print(apk1,apk2):
    import apkid.apkid as apkid
    options = apkid.Options(
        timeout=45,
        verbose=False,
        entry_max_scan_size=100 * 1024 * 1024,
        recursive=True,
    )
    output = apkid.OutputFormatter(
        json_output=True,
        output_dir=None,
        rules_manager=apkid.RulesManager(),
        include_types=False
    )
    rules = options.rules_manager.load()
    scanner = apkid.Scanner(rules, options)
    res1 = scanner.scan_file(apk1)
    res2 = scanner.scan_file(apk2)
#    scanner.scan(apk)
    try:
        findings1 = output._build_json_output(res1)['files']
        findings2 = output._build_json_output(res2)['files']
    except AttributeError:
        # apkid >= 2.0.3
        findings1 = output.build_json_output(res1)['files']
        findings2 = output.build_json_output(res2)['files']
    sanitized = {}
    match = True
    if len(findings1) != len(findings2):
        match = False
    else:
        for i in range(len(findings1)):
            filename1 = findings1[i]['filename']
            sanitized[filename1] = findings1[i]['matches']
            if findings1[i]['matches'] != findings2[i]['matches']:
                match = False
    scanner.scan(apk1)
    if match:
        print("\x1b[6;32;40mIDENTICAL\x1b[0m")
    else:
        print("\x1b[6;31;40mNOT IDENTICAL\x1b[0m")
        scanner.scan(apk2)

def agdiff(dx1,dx2):
    print("CHANGED CLASSES:")
    classes1 = list(dx1.get_classes())
    classes2 = list(dx2.get_classes())
    classes1 = sorted(classes1, key=lambda x:x.name)
    classes2 = sorted(classes2, key=lambda x:x.name)

    i = 0
    j = 0    
    while i != len(classes1) and j != len(classes2):
        if (classes1[i].name) == (classes2[j].name):
            i+=1
            j+=1
        elif (classes1[i].name) < (classes2[j].name):
            print(classes1[i].name)
            i+=1
        elif (classes1[i].name) > (classes2[j].name):
            print(classes2[j].name)
            j+=1
    if i == len(classes1):
        while j != len(classes2):
            print(classes2[j].name)
            j+=1
    elif j == len(classes2):
        while i != len(classesi):
            print(classes1[i].name)
            i+=1
                
    print("CHANGED METHODS:")
    methods1 = list(dx1.get_methods())
    methods2 = list(dx2.get_methods())
    methods1 = sorted(methods1, key=lambda x:x.full_name)
    methods2 = sorted(methods2, key=lambda x:x.full_name)

    i = 0
    j = 0
    while i != len(methods1) and j != len(methods2):
        if (methods1[i].full_name) == (methods2[j].full_name):
            i+=1
            j+=1
        elif (methods1[i].full_name) < (methods2[j].full_name):
            print(methods1[i].full_name)
            i+=1
        elif (methods1[i].full_name) > (methods2[j].full_name):
            print(methods2[j].full_name)
            j+=1
    if i == len(methods1):
        while j != len(methods2):
            print(methods2[j].full_name)
            j+=1
    elif j == len(methods2):
        while i != len(methodsi):
            print(methods1[i].full_name)
            i+=1

    print("CHANGED FIELDS:")
    fields1 = list(dx1.get_fields())
    fields2 = list(dx2.get_fields())
    def get_full_name(x):
        if x.field.access_flags_string is not None:
            return x.field.class_name+x.field.name+x.field.proto+x.field.access_flags_string
        else:
            return x.field.class_name+x.field.name+x.field.proto
    fields1 = sorted(fields1, key=get_full_name)
    fields2 = sorted(fields2, key=get_full_name)

    i = 0
    j = 0
    while i != len(fields1) and j != len(fields2):
        if (get_full_name(fields1[i])) == (get_full_name(fields2[j])):
            i+=1
            j+=1
        elif (get_full_name(fields1[i])) < (get_full_name(fields2[j])):
            print(fields1[i].field)
            i+=1
        elif (get_full_name(fields1[i])) > (get_full_name(fields2[j])):
            print(fields2[j].field)
            j+=1
    if i == len(fields1):
        while j != len(fields2):
            print(fields2[j].field)
            j+=1
    elif j == len(fields2):
        while i != len(fieldsi):
            print(fields1[i].field)
            i+=1


def print_usage(prog):
    print(__doc__.format(prog=prog).strip())

if __name__ == '__main__':
    args = sys.argv
    prog = os.path.basename(args.pop(0))

    if '-h' in args or '--help' in args:
        print_usage(prog)
        exit(0)

    if len(args) < 2:
        print_usage(prog)
        exit(1)

    file2 = args.pop(-1)
    file1 = args.pop(-1)
    # check if files have same extension and if its .apk
    if os.path.splitext(file1)[1]==os.path.splitext(file2)[1]==".apk":
        if '--resdiff' in args:
            subprocess.call(['apktool','d',file1,'-f','-o','/tmp/apk1'], stderr=subprocess.STDOUT)
            subprocess.call(['apktool','d',file2,'-f','-o','/tmp/apk2'], stderr=subprocess.STDOUT)
            exit(resdiff("/tmp/apk1","/tmp/apk2"))
        if '--apkid' in args:
            exit(apkid_print(file1, file2))
        if '--agdiff' in args:
            a1, d1, dx1 = AnalyzeAPK(file1)
            a2, d2, dx2 = AnalyzeAPK(file2)
            #for word in KEYWORDLIST:
            #    for field in dx1.find_fields(fieldname="(?i).*"+word+".*"):
            #        print(field.field)

            exit(agdiff(dx1,dx2))
        if '--amdiff' in args:
            a1, d1, dx1 = AnalyzeAPK(file1)
            a2, d2, dx2 = AnalyzeAPK(file2)
            xml1 = a1.get_android_manifest_xml()
            xml2 = a2.get_android_manifest_xml()
            exit(listdiffs(xml1, xml2))
    else:
        xml1 = lxml.etree.parse(file1).getroot()
        xml2 = lxml.etree.parse(file2).getroot()
    if '--amdiff' in args:
        exit(listdiffs(xml1, xml2))

    print_usage(prog)
    exit(1)
