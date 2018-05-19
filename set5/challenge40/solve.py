from binascii import hexlify, unhexlify
import gmpy2

def chinese_remainder_theorem(items):
    N = 1
    for a, n in items:
        N *= n

    result = 0
    for a, n in items:
        m = N // n
        i = gmpy2.invert(m,n)
        result += a * i * m
    return result % N

class RSA:
	def __init__(self, primes):
		self.p = primes[0]
		self.q = primes[1]
		
		self.n = self.p*self.q
		self.phi = (self.p-1)*(self.q-1)

		self.e = 3
		self.d = gmpy2.invert(self.e, self.phi)

	def encrypt(self, m):
		return pow(m, self.e, self.n)

	def decrypt(self, c):
		return pow(c, self.d, self.n)


if __name__ == "__main__":
	gmpy2.get_context().precision = 8000

	primes1 = [30002754019704757557704669638439818914586783279134589468420036481102352427427467980323037625803050320676617366340142729335282904072785557390379870247405833432554050834048745003510363481580682190774428237974383206559804176682203778789834645879963731857034394014327957384660838255483513517910960211164589920610425998661315669400273111981133335094146320641407523553916121825186459624306932090098434011110030686194889789487369426126096188535314445085789208661359506827439200799895457028097786919160045362097775840386197085981088880090614620634960814537430939102825477149587682850102924370108642480671955921489221041983209,
			   30263925796144376010297458611444678587891796139885744243576775568198923119308726072515937121298016192783262621448001001753674561427198565146278290415115935228700696144678339002897761358281932780955424020297594177831504467280118108278992442126181390703404897114622355192351145709842292680875376309319342167542933408392818636542215758932523622482273767304401383297387828702421439170710579073029973769927808080223462384535319276254554000011314354924075652045169939253557909000829528422708042133863394804538427010108460586749127830633127494068838793271378184006233305946926627099921417360254101661437137492242157915253467]

	primes2 = [31012330212514541723880810929027823743999869506099880125017108120348902847141853432705995011523062182174453336452072484037932708860517221563724974227836923661472305822392753045811009283858246516038256898612435100722570832387113513704653803993385350169394895190005054714937061954190800146849357608421657354607627539930072605937610008832452347087003851183831714177216393060533859122987049113719347697868092218941070178527586619414047681166584642268695912584702994629982178527034842080336901712360684379130783452105410524620899774627934383663809938525534635722016709412699742249559833620241236567305456795170717636621537,
			   24653432103043487055626690665130433190102989519487040323318488753656649601505518021922552471380719759687119659504590983827144571619847155779530671010260605548795422471353195445965641246648247653017463071855622707310384527257975531576155502199381578027580438483113499291216492630978683906553702508499300267763752774169584923186034981194939181464999142042143382143354080216945990899925498952127366122277331920013328824502908723223669658856567573493284868630890915270733770615791270421191715245096541215606155361988984764665031386425548129159491200730789642563166803431613974503670032951447175765711016738098827140381077]

	primes3 = [30805059852287160122957248911186679364960273524236020883805005688220197123126356657625951593459270103231525106467689859524245226734110234619051259147346736870149228059230493255058847687646192990423251369559805998195745315609135933269544605337131873257348590294457884365337789919540671685178540677106245492581306330388491446679233932853848343391340532946211039874709059240665801926041046610657028449589305092501771144756204471507229402358755255892021788413179097845618928441404439907976412082359961592609252373900304458800511926184886042019387013365449891169312017527439955157593998726253267351300739534780604180713289,
			   27297639563188087653576662680029936519130479096290448187748541405447172718835471444976771797792729690588827562320545483926313020553395330806627963469146271150711010469983774439884552844875210728526836458267586579920060362528237344759363261713301544350357627060401679665317767510579003826901809916463551359666381611651493121237771718799819959286703062496095216016298467510359574197729720936128619114056723799694672587819109321613130531333241643380540213395447338299020555688612569656502718993933679590452848338346536877237720469663074824006068558168158905457934657558912307723222626840667182375557633938247402679522157]

	rsa1 = RSA(primes1)
	rsa2 = RSA(primes2)
	rsa3 = RSA(primes3)

	m = int(hexlify(b"rsa_broadcast_string").decode(), 16)

	c1 = rsa1.encrypt(m)
	c2 = rsa2.encrypt(m)
	c3 = rsa3.encrypt(m)

	n1 = primes1[0]*primes1[1]
	n2 = primes2[0]*primes2[1]
	n3 = primes3[0]*primes3[1]

	C = chinese_remainder_theorem([(c1, n1), (c2, n2), (c3, n3)])
	M = gmpy2.cbrt(C)

	print(unhexlify(hex(int(M))[2:]))