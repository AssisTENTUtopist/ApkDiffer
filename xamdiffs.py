#!/usr/bin/env python
"""
Usage: {prog} [OPTION] FILE1 FILE2
Compare two XML files, ignoring element and attribute order.
OPTIONS
    --list		output a list of diffs in attributes and nodes
Any extra options are passed to the `diff' command.
"""
import sys
import os
import io
import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile
import subprocess

NAME = '{http://schemas.android.com/apk/res/android}name'
new_attribs=[]
new_nodes=[]
old_attribs=[]
old_nodes=[]
changed_attribs=[]

def attr_str(k, v):
    return "{}=\"{}\"".format(k,v)

def node_str(n, level):
    attrs = sorted(n.attrib.items(), key=sort_attrs)
    astr = "\n".join(attr_str(indent(k,level+1),v) for k,v in attrs)
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

def indent(s, level):
    return "  " * level + s

def write_sorted(stream, node, level=0):
    subnodes = list(node)
    if subnodes:
        subnodes.sort(key=lambda n: node_str(n,level))

        if len(node.attrib) == 0:
            stream.write(indent("<" + node.tag + ">", level))

        else:
            stream.write(indent("<" + node_str(node,level), level) + "\n" + indent(">", level))

        stream.write("\n")
        for subnode in subnodes:
            write_sorted(stream, subnode, level + 1)

        stream.write(indent("</" + node.tag + ">\n", level))

    else:
        stream.write(indent("<" + node_str(node,level) + "\n", level) + indent("/>\n", level))

def node_diff(n1,n2):
    attrs1 = sorted(n1.attrib.items(), key=sort_attrs)
    attrs2 = sorted(n2.attrib.items(), key=sort_attrs)
    return set(attrs1)^set(attrs2)

def node_name(node):
    if node.find('[@'+NAME+']') is not None:
        return node.tag + node.attrib[NAME]
    return node.tag

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
    subnodes1.sort(key=lambda n: node_str(n,0))
    subnodes2.sort(key=lambda n: node_str(n,0))
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
                        old_nodes.append([write_nodes(subnodes1[i]),node_name(node1)])
                        i += 1
                    else:
                        new_nodes.append([write_nodes(subnodes2[j]),node_name(node2)])
                        j += 1
                elif subnodes1[i].find('[@'+NAME+']') is None and subnodes2[j].find('[@'+NAME+']') is None:
                    write_diffed(subnodes1[i], subnodes2[j])
                    i += 1
                    j += 1
    elif subnodes1 or subnodes2:
        if len(subnodes1)==0:
            for subnode2 in subnodes2:
                new_nodes.append([write_nodes(subnode2),node_name(node2)])
        else:
            for subnode1 in subnodes1:
                old_nodes.append([write_nodes(subnode1),node_name(node1)])

def write_nodes(node, level=0):
    subnodes = list(node)
    s=""
    if subnodes:
        subnodes.sort(key=lambda n: node_str(n,level))

        if len(node.attrib) == 0:
            s+=(indent("<" + node.tag + ">", level))

        else:
            s+=(indent("<" + node_str(node,level), level) + "\n" + indent(">", level))

        s+="\n"
        for subnode in subnodes:
            s+=write_nodes(subnode, level + 1)

        s+=indent("</" + node.tag + ">\n", level)

    else:
        s+=indent("<" + node_str(node,level) + "\n", level) + indent("/>\n", level)
    return s

if sys.version_info < (3, 0):
    # Python 2
    import codecs
    def unicode_writer(fp):
        return codecs.getwriter('utf-8')(fp)
else:
    # Python 3
    def unicode_writer(fp):
        return fp

def xmldiffs(file1, file2, diffargs=["-u"]):
    tree = ET.parse(file1)
    tmp1 = unicode_writer(NamedTemporaryFile('w'))
    write_sorted(tmp1, tree.getroot())
    tmp1.flush()

    tree = ET.parse(file2)
    tmp2 = unicode_writer(NamedTemporaryFile('w'))
    write_sorted(tmp2, tree.getroot())
    tmp2.flush()

    args = [ "diff" ]
    args += diffargs
    args += [ "--label", file1, "--label", file2 ]
    args += [ tmp1.name, tmp2.name ]
    return subprocess.call(args)

def listdiffs(file1, file2):
    write_diffed(ET.parse(file1).getroot(),ET.parse(file2).getroot())
    if new_attribs:
        print("NEW ATTRIBUTES")
        for attrib in new_attribs:
            print(attrib[1] + ":\n", attrib[0])
    if old_attribs:
        print("\nOLD ATTRIBUTES")
        for attrib in old_attribs:
            print(attrib[1] + ":\n", attrib[0])
    if changed_attribs:
        print("\nCHANGED ATTRIBUTES")
        for attrib in changed_attribs:
            print(attrib[1] + ":\n", attrib[0])
    if new_nodes:
        print("\nNEW NODES")
        for node in new_nodes:
            print(node[1] + ":\n" + node[0])
    if old_nodes:
        print("\nOLD NODES")
        for node in old_nodes:
            print(node[1] + ":\n" + node[0])

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

    if '--list' in args:
        exit(listdiffs(file1, file2))

    diffargs = args if args else ["-u"]

    exit(xmldiffs(file1, file2, diffargs))
