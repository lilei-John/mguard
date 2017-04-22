import sys, os, struct, ctypes, argparse

def ERROR(x): print "!!ERROR!! "+x

def ERROR(x,exception):
    print "!!ERROR!! "+x
    print "    => ", exception

def WARNING(x): print "!!WARNING!! "+x

class MSummary:
    pass



def main():
    ver='1.01'
    inputFile=sys.argv[1]
    headers=1
    line_count=0
    out=None
    if len(sys.argv) >2:
        out=open(sys.argv[2],'w')

    smap={}
    rmap={}

    for line in open(inputFile):
        line=line.strip()

        if line.startswith("MGUARD version '1.0'"):
            ver='1.0'


        if headers !=0 and ver=='1.01' and line.startswith("========@"):
            out.write("\n")
            out.write(':[TYPE]:[BACKTRACE_ID]:[TOTAL_UNFREED_SIZE]:[COUNT]:[BACKTRACE]'+"\n")
            out.write(line+"\n")
            headers=0
        elif headers!=0 and ver=='1.0' and line_count>=7:
            out.write("\n")
            headers=0

        if headers:
            out.write(line+"\n")

        if line.startswith(":F"):
            tokens=line.split(":")
            k=tokens[2].strip()
            smap[k]=tokens[6].strip()
        line_count+=1

    for line in open(inputFile):
        line=line.strip()
        if line.startswith(":M"):
            tokens=line.split(":")
            k=tokens[5].strip()
            m=None
            if not rmap.has_key(k):
                m=MSummary()
                m.size=0
                m.count=0
                m.id=k
                rmap[k]=m
            else:
                m=rmap[k]

            m.count+=1
            m.size+=int(tokens[3])

    keys=rmap.keys()
    keys.sort()

    total_mem=0
    for k in keys:
        m=rmap[k]
        total_mem+=m.size
        str=":S:{}:{}:{}:{}".format(k,m.size,m.count,"--" if not smap.has_key(k) else smap[k])
##        print '>>>> '+str
        if out is not None:
            out.write(str)
            out.write("\n")


    if out is not None:
        out.write("\nTotal Counting Memory Size:{}\n".format(total_mem))
        out.close()




if __name__ == "__main__":
    main()
