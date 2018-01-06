#include <iostream>
#include <conio.h>
#include <time.h>
using namespace std;

// Lớp chứa các phương thức phụ trợ
class Utility{
public:
static int SumMod(int a, int b, int n)
{
	while (a > n)
		a -= n;
	while (a<0)
		a += n;
	while (b > n)
		b -= n;
	while (b<0)
		b += n;
	int P = a + b;
	if (P > n) 
		return P-n;
	/*if (P < 0)
		return a - n + b;*/
	return P;
	//return a%n + b%n;
}

static int MulMod(int a, int b, int n)
{
	int S;
	if ((b & 1) == 0)
		S = 0;	
	else
		S = a;
	b = b >> 1;
	while (b>0)
	{
		a = SumMod(a, a, n);
		if ((b & 1) == 1)
			S = SumMod(S, a, n);
		b = b >> 1;
	}
	return S;
}

static int PowMod(int a, int b, int n)
{
	int y = 1;
	if (b == 0)
		return y;
	int A = a;
	if ((b & 1) == 1)
		y = a;
	b = b >> 1;
	while (b > 0)
	{
		A = MulMod(A, A, n);
		if ((b & 1) == 1)
			y = MulMod(A, y, n);
		b = b >> 1;
	}
	return y;
}
static int gcd(int a,int b)
{
	int g=0;
	while(((a&1)==0)&&((b&1)==0))
	{
		a = a >> 1;
		b = b >> 1;
		g++;
	}
	while (a>0)
	{
		while((a&1)==0)
			a=a>>1;
		while((b&1)==0)
			b=b>>1;
		if(a>=b)
		{
			a=(a-b)>>1;
		}
		else
			b=(b-a)>>1;
	}
	b=b<<g;
	return b;
}
static void Bezout(int a, int b, int &x, int &y)
{
	int u = a, v = b;
	int X = 1, Y = 0;
	x = 0;
	y = 1;
	while (u > 0)
	{
		while ((u & 1) == 0)
		{
			u = u >> 1;
			if (((X & 1) == 0) && ((Y & 1) == 0))
			{
				X = X >> 1;
				Y = Y >> 1;
			}
			else
			{
				X = (X + b) >> 1;
				Y = (Y - a) >> 1;
			}
		}
		while ((v & 1) == 0)
		{
			v = v >> 1;
			if (((x & 1) == 0) && ((y & 1) == 0))
			{
				x = x >> 1;
				y = y >> 1;
			}
			else
			{
				x = (x + b) >> 1;
				y = (y - a) >> 1;
			}
		}
		if (u >= v)
		{
			u -= v;
			X -= x;
			Y -= y;
		}
		else
		{
			v -= u;
			x -= X;
			y -= Y;
		}
	}
}
static bool PrimeTest(int n)
{
	if (n < 2)
		return false;
	if ((n == 2) || (n == 3))
		return true;
	int m=n-1;
	int r=0;
	while ((m&1)==0)
	{
		r++;
		m=m>>1;
	}
	int t;
	int i = 1;
	do
	{
		t = PowMod(3, (1 << i)*m, n);
		if((t!=1)&&(t!=n-1))
			return false;		
		t = PowMod(2, (1 << i)*m, n);
		if ((t != 1) && (t != n - 1))
			return false;
		i++;
	}
	while (i <= r);
	
	return true;
}
static int prime_generator(int size)
{
	int t = (1 << (size - 1));
	srand(time(NULL));
	int i = t + 1 + rand()%t;
	if ((i & 1) == 0)
		i--;
	t = t << 1;
	while (i < t)
	{
		if (PrimeTest(i))
			return i;
		else
			i += 2;
	}
}
static int CRT(int size, int p[], int a[])
{
	int n = 1;
	for (int i = 0; i < size - 1; i++)
	{
		for (int j = i + 1; j < size; j++)
		{
			if (gcd(p[i], p[j]) != 1)
			{
				cout << "He khong phai la he dong du!";
				return -1;
			}
		}
		n *= p[i];
	}
	n *= p[size - 1];
	
	int m = 0;
	int *N = new int[size];
	int *M = new int[size];	
	for (int i = 0; i < size; i++)
	{
		N[i] = 1;
		for (int j = 0; j < size; j++)
		{
			if (i == j)
				continue;
			N[i] *= p[j];
		}
		int t;
		Bezout(N[i], p[i], M[i], t);
		M[i] = MulMod(M[i], a[i], n);
		t = MulMod(M[i], N[i], n);
		m = SumMod(m, t, n);		
	}	
	delete[] M;
	delete[] N;	
	return m;
}
};


class Crypto{
public:
	// 1 - Giải pháp RSA
	static void RSA_initialize(int size, int &d, int &e, int&p, int&q)//xuất thêm giá trị p và q để giải mã nhanh và công bố n
	{
		p = Utility::prime_generator(size);
		q = Utility::prime_generator(size + 1);
		srand(time(NULL));
		int k = rand() % (2 * size - 1) + 1;
		int phi = (p - 1)*(q - 1);
		int n = p*q;
		e = (1 << k) + 1;
		while (Utility::gcd(e, phi) != 1)//vì phi chẵn nên ta chỉ xét các giá trị e lẻ
		{
			e = e + 2;
		}
		int t;
		Utility::Bezout(e, phi, d, t);		
	}
	static int RSA_encrypt(int n, int e, int m)
	{
		return Utility::PowMod(m, e, n);
	}
	static int RSA_decrypt(int n, int d, int c)
	{
		return Utility::PowMod(c, d, n);
	}
	static int RSA_decryptCRT(int p, int q, int d, int c)
	{
		if ((d < p - 1) || (d < q - 1)) //nếu d<p-1 hay d<p-2 thì giải mã nhanh bằng CRT vô nghĩa
			return Utility::PowMod(c, d, p*q);
		int d1, d2;
		d1 = d % (p - 1);
		d2 = d % (q - 1);
		int P[2] = { p, q };
		int a[2] = { Utility::PowMod(c, d1, p), Utility::PowMod(c, d2, q) };
		return Utility::CRT(2, P, a);
	}

	// 2 - Mô hình Diffie Hellman

	static bool isRoot(int g, int p) //kiểm tra xem g có phải phần tử sinh của Zp
	{
		for (int i = 2; i < p - 1; i++)
		{
			if (Utility::PowMod(g, i, p) == 1)
				return false;
			return true;
		}
	}
	static int primitiveRoot(int p)//trả về phần tử sinh của vành Zp với p nguyên tố
	{	
		for (int g = 2;g < p - 1; g++)
		{
			if (isRoot(g, p))
				return g;
		}		
	}
	static int DiffieHellman_Individual(int g, int n, int a)
	{
		return Utility::PowMod(g, a, n);
	}
	static int DiffieHellman(int n, int x, int received)
	{
		return Utility::PowMod(received, x, n);
	}
};

// Hàm main test chương trình
void main()
{
	cout << Utility::PowMod(10, 43, 77) << endl;
	cout << Utility::PowMod(128, 7, 13)<<endl;
	cout << Utility::PowMod(128, 3, 17);
	cout << "Test thuat toan RSA:" << endl;
	int d, e, p, q;
	Crypto::RSA_initialize(15, d, e, p, q);
	int n = p*q;
	cout << "Nhap du lieu test:";
	int m;
	cin >> m;
	int c = Crypto::RSA_encrypt(n, e, m);
	cout << "Du lieu duoc ma hoa: " << c << endl;
	cout << "Du lieu duoc giai ma: " << Crypto::RSA_decrypt(n, d, c) << endl;
	cout << "Du lieu duoc giai ma nhanh: " << Crypto::RSA_decryptCRT(p, q, d, c) << endl;
	cout << "Test mo hinh Diffie Hellman:" << endl;
	p = Utility::prime_generator(15);
	int g = Crypto::primitiveRoot(p);
	srand(time(NULL));
	int a = rand();
	cout << a;
	int B_received = Crypto::DiffieHellman_Individual(g, p, a);
	cout << "Khoa g^a Alice gui cho Bob: " << B_received << endl;
	srand(time(NULL));
	int b = rand();
	int A_received = Crypto::DiffieHellman_Individual(g, p, b);
	cout << "Khoa g^b Bob gui cho Alice: " << B_received << endl;
	cout << "Khoa bi mat chung (g^a)^b cua Bob tinh duoc:" << Utility::PowMod(B_received, p, b) << endl;
	cout << "Khoa bi mat chung (g^b)^a cua Alice tinh duoc:" << Utility::PowMod(B_received, p, a) << endl;
	//Bob và Alice có thể gửi dữ liệu m bằng cách gửi c = MulMod(m,g^ab,p); giải mã bằng cách tìm d = (g^ab)^-1 tính được m=cd  
	_getch();
}



