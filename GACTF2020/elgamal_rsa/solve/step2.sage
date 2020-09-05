from Crypto.Util.number import *

def solve():
    secret=329380824451982777596468080979390700896875051159309053251427777390225223390054462862874890632092714850180031743329031313028975903871751004003831036860000454098274963081490031808010876171935539110201531253322208564941373067673598629247111527738724700328114569409692796434368030258427126193825227856160081569366870307559297674909108870298864572520476006338972072593434914773857347865349086098662711283463352902488164071184362082990162654586995346553108747183805073294471613391819978413596510467204977114038549473397779377039088475929677184284430986636686769839308217865627271293739711926018699557041530631349486791876338842184994986024157099233298972714917732995013317087756483L
    facs=[(53864521104821743450369,1),(653551912583,15),(5523725851828117200525990541108447421540611178749470148162289329,1),(189405463748811642227236342349480536763372956028952226524502488361894394181865970770370984808206708395199610731759930125343374631146498216724222173176836769059294784252555525731281951678489,1),(802576647765917,3),(104280142799213,1),(12331277924139845761101836163934769428376437554550730297750419620927293,1),(644129275539176805067226850889,2),(232087313537,3)]
    e=0x1296L
    cip=255310806360822158306697936064463902328816816156848194779397173946813224291656351345682266227949792774097276485816149202739762582969208376195999403112665514848825884325279574067341653685838880693150001066940379902609411551128810484902428845412055387955258568610350610226605230048821754213270699317153844590496606931431733319116866235538921198147193538906156906954406577796507390570080177313707462469835954564824944706687157852157673146976402325057144745208116022973614795377968986322754779469798013426261911408914756488145211933799442123449261969392169406969410065018032795960230701484816708147958190769470879211953704222809883281592308316942052671516609231501663363123562942L
    ms2=[]
    mods=[]
    for fac in facs:
        phi=pow(fac[0],fac[1]-1)*(fac[0]-1)
        if gcd(phi,e)==2:
            M=pow(fac[0],fac[1])
            t=inverse(e/2,phi)
            ms2.append(power_mod(cip,t,M))
            mods.append(M)
    m2=crt(ms2,mods)
    return long_to_bytes(m2.sqrt())

if __name__=='__main__':
    print solve()
