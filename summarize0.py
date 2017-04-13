import sys, os, struct, ctypes, argparse

def ERROR(x): print "!!ERROR!! "+x

def ERROR(x,exception): 
    print "!!ERROR!! "+x
    print "    => ", exception

def WARNING(x): print "!!WARNING!! "+x   

class MSummary:
    pass



def main():
    inputFile=sys.argv[1]
    
    out=None
    if len(sys.argv) >2:
        out=open(sys.argv[2],'w')

    smap={}
    rmap={}
    
    for line in open(inputFile):
        line=line.strip()
        if line.startswith(":F"):
            tokens=line.split(":")
            k=tokens[2].strip()
            smap[k]=tokens[6].strip()
             
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

    for k in keys:
        m=rmap[k]

        str=":S:{}:{}:{}:{}".format(k,m.size,m.count,"--" if not smap.has_key(k) else smap[k])
        print '>>>> '+str
        if out is not None:
            out.write(str)
            out.write("\n")

    if out is not None:
        out.close()

        
    

if __name__ == "__main__":
    main()
