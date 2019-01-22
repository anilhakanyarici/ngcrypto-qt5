#include "ecc.h"
#include "drbg.h"
#include "hmac.h"

#include <memory>

#include <QDebug>
#include <QElapsedTimer>

class ECInteger
{
    struct pimpl;
    QSharedPointer<pimpl> _pimpl;

public:
    ECInteger();
    ECInteger(int value);
    ECInteger(uint value);
    ECInteger(long value);
    ECInteger(ulong value);
    ECInteger(char *bytes, long bytes_length, int sign, bool big_endian = false);
    ECInteger(const QByteArray &bytes, int sign,  bool big_endian = false);

    static inline ECInteger zero() { return ECInteger(0u); }
    static inline ECInteger one() { return ECInteger(1u); }

    bool isZero() const;
    bool isOne() const;
    bool isNegative() const;
    bool isPositive() const;
    bool isEven() const;
    bool isOdd() const;
    int sign() const;
    int digitLength() const;
    long bytesLength() const;
    long bitsLength() const;
    uint firstDigit() const;
    uint *data() const;
    char *bytesData() const;

    ECInteger &add(const ECInteger &value);
    ECInteger &sub(const ECInteger &value);
    ECInteger &mul(const ECInteger &value);
    ECInteger &div(const ECInteger &divisor);
    ECInteger &rem(const ECInteger &modulus);
    ECInteger &divrem(const ECInteger &divisor, ECInteger &remainder);

    static ECInteger add(const ECInteger &left, const ECInteger &right);
    static ECInteger sub(const ECInteger &left, const ECInteger &right);
    static ECInteger mul(const ECInteger &left, const ECInteger &right);
    static ECInteger div(const ECInteger &dividend, const ECInteger &divisor);
    static ECInteger rem(const ECInteger &dividend, const ECInteger &divisor);
    static ECInteger divrem(const ECInteger &dividend, const ECInteger &divisor, ECInteger &remainder);

    ECInteger &bitshift(const int &shift);
    ECInteger &rightShift(const int &shift);
    ECInteger &leftShift(const int &shift);
    ECInteger &negate();
    ECInteger &square();
    ECInteger &cube();
    ECInteger &abs();
    ECInteger &pow(uint exponent);

    int bit(const long &pos) const;
    ECInteger clone() const;
    QVector<int> nonAdjacentForm(const int &window) const;
    static ECInteger parse(const char *chars);
    static ECInteger parse(const QString &value);
    static ECInteger parseFromHex(const QString &hexstr);
    static ECInteger random(const long &bytes_length);
    static void swap(ECInteger &l, ECInteger &r);

    static int compare(const ECInteger &left, const ECInteger &right);

    inline friend ECInteger operator +(const ECInteger &left, int right) { return ECInteger::add(left, ECInteger(right)); }
    inline friend ECInteger operator -(const ECInteger &left, int right) { return ECInteger::sub(left, ECInteger(right)); }
    inline friend ECInteger operator *(const ECInteger &left, int right) { return ECInteger::mul(left, ECInteger(right)); }
    inline friend ECInteger operator /(const ECInteger &left, int right) { return ECInteger::div(left, ECInteger(right)); }
    inline friend ECInteger operator %(const ECInteger &left, int right) { return ECInteger::rem(left, ECInteger(right)); }
    inline friend ECInteger operator +(const ECInteger &left, uint right) { return ECInteger::add(left, ECInteger(right)); }
    inline friend ECInteger operator -(const ECInteger &left, uint right) { return ECInteger::sub(left, ECInteger(right)); }
    inline friend ECInteger operator *(const ECInteger &left, uint right) { return ECInteger::mul(left, ECInteger(right)); }
    inline friend ECInteger operator /(const ECInteger &left, uint right) { return ECInteger::div(left, ECInteger(right)); }
    inline friend ECInteger operator %(const ECInteger &left, uint right) { return ECInteger::rem(left, ECInteger(right)); }
    inline friend ECInteger operator +(const ECInteger &left, long right) { return ECInteger::add(left, ECInteger(right)); }
    inline friend ECInteger operator -(const ECInteger &left, long right) { return ECInteger::sub(left, ECInteger(right)); }
    inline friend ECInteger operator *(const ECInteger &left, long right) { return ECInteger::mul(left, ECInteger(right)); }
    inline friend ECInteger operator /(const ECInteger &left, long right) { return ECInteger::div(left, ECInteger(right)); }
    inline friend ECInteger operator %(const ECInteger &left, long right) { return ECInteger::rem(left, ECInteger(right)); }
    inline friend ECInteger operator +(const ECInteger &left, ulong right) { return ECInteger::add(left, ECInteger(right)); }
    inline friend ECInteger operator -(const ECInteger &left, ulong right) { return ECInteger::sub(left, ECInteger(right)); }
    inline friend ECInteger operator *(const ECInteger &left, ulong right) { return ECInteger::mul(left, ECInteger(right)); }
    inline friend ECInteger operator /(const ECInteger &left, ulong right) { return ECInteger::div(left, ECInteger(right)); }
    inline friend ECInteger operator %(const ECInteger &left, ulong right) { return ECInteger::rem(left, ECInteger(right)); }
    inline friend ECInteger operator +(const ECInteger &left, const ECInteger &right) { return ECInteger::add(left, right); }
    inline friend ECInteger operator -(const ECInteger &left, const ECInteger &right) { return ECInteger::sub(left, right); }
    inline friend ECInteger operator *(const ECInteger &left, const ECInteger &right) { return ECInteger::mul(left, right); }
    inline friend ECInteger operator /(const ECInteger &left, const ECInteger &right) { return ECInteger::div(left, right); }
    inline friend ECInteger operator %(const ECInteger &left, const ECInteger &right) { return ECInteger::rem(left, right); }

    inline ECInteger &operator +=(int value){ return this->add(value); }
    inline ECInteger &operator +=(uint value){ return this->add(value); }
    inline ECInteger &operator +=(long value){ return this->add(value); }
    inline ECInteger &operator +=(ulong value){ return this->add(value); }
    inline ECInteger &operator +=(const ECInteger &value){ return this->add(value); }
    inline ECInteger &operator -=(int value){ return this->sub(value); }
    inline ECInteger &operator -=(uint value){ return this->sub(value); }
    inline ECInteger &operator -=(long value){ return this->sub(value); }
    inline ECInteger &operator -=(ulong value){ return this->sub(value); }
    inline ECInteger &operator -=(const ECInteger &value){ return this->sub(value); }
    inline ECInteger &operator *=(int value){ return this->mul(value); }
    inline ECInteger &operator *=(uint value){ return this->mul(value); }
    inline ECInteger &operator *=(long value){ return this->mul(value); }
    inline ECInteger &operator *=(ulong value){ return this->mul(value); }
    inline ECInteger &operator *=(const ECInteger &value){ return this->mul(value); }
    inline ECInteger &operator /=(int value){ return this->div(value); }
    inline ECInteger &operator /=(uint value){ return this->div(value); }
    inline ECInteger &operator /=(long value){ return this->div(value); }
    inline ECInteger &operator /=(ulong value){ return this->div(value); }
    inline ECInteger &operator /=(const ECInteger &value){ return this->div(value); }
    inline ECInteger &operator %=(int value){ return this->rem(value); }
    inline ECInteger &operator %=(uint value){ return this->rem(value); }
    inline ECInteger &operator %=(long value){ return this->rem(value); }
    inline ECInteger &operator %=(ulong value){ return this->rem(value); }
    inline ECInteger &operator %=(const ECInteger &value){ return this->rem(value); }

    inline friend ECInteger operator >>(const ECInteger &value, int shift) { return value.clone().bitshift(-shift); }
    inline friend ECInteger operator <<(const ECInteger &value, int shift) { return value.clone().bitshift(shift); }

    inline ECInteger &operator >>=(int shift) { return this->bitshift(-shift); }
    inline ECInteger &operator <<=(int shift) { return this->bitshift(shift); }

    inline friend bool operator <(int left, const ECInteger &right) { return ECInteger::compare(left, right) == -1; }
    inline friend bool operator >(int left, const ECInteger &right) { return ECInteger::compare(left, right) == 1; }
    inline friend bool operator ==(int left, const ECInteger &right) { return ECInteger::compare(left, right) != 0; }
    inline friend bool operator !=(int left, const ECInteger &right) { return ECInteger::compare(left, right) == 0; }
    inline friend bool operator <=(int left, const ECInteger &right) { return ECInteger::compare(left, right) < 1; }
    inline friend bool operator >=(int left, const ECInteger &right) { return ECInteger::compare(left, right) > -1; }
    inline friend bool operator <(uint left, const ECInteger &right) { return ECInteger::compare(left, right) == -1; }
    inline friend bool operator >(uint left, const ECInteger &right) { return ECInteger::compare(left, right) == 1; }
    inline friend bool operator ==(uint left, const ECInteger &right) { return ECInteger::compare(left, right) != 0; }
    inline friend bool operator !=(uint left, const ECInteger &right) { return ECInteger::compare(left, right) == 0; }
    inline friend bool operator <=(uint left, const ECInteger &right) { return ECInteger::compare(left, right) < 1; }
    inline friend bool operator >=(uint left, const ECInteger &right) { return ECInteger::compare(left, right) > -1; }
    inline friend bool operator <(long left, const ECInteger &right) { return ECInteger::compare(left, right) == -1; }
    inline friend bool operator >(long left, const ECInteger &right) { return ECInteger::compare(left, right) == 1; }
    inline friend bool operator ==(long left, const ECInteger &right) { return ECInteger::compare(left, right) != 0; }
    inline friend bool operator !=(long left, const ECInteger &right) { return ECInteger::compare(left, right) == 0; }
    inline friend bool operator <=(long left, const ECInteger &right) { return ECInteger::compare(left, right) < 1; }
    inline friend bool operator >=(long left, const ECInteger &right) { return ECInteger::compare(left, right) > -1; }
    inline friend bool operator <(ulong left, const ECInteger &right) { return ECInteger::compare(left, right) == -1; }
    inline friend bool operator >(ulong left, const ECInteger &right) { return ECInteger::compare(left, right) == 1; }
    inline friend bool operator ==(ulong left, const ECInteger &right) { return ECInteger::compare(left, right) != 0; }
    inline friend bool operator !=(ulong left, const ECInteger &right) { return ECInteger::compare(left, right) == 0; }
    inline friend bool operator <=(ulong left, const ECInteger &right) { return ECInteger::compare(left, right) < 1; }
    inline friend bool operator >=(ulong left, const ECInteger &right) { return ECInteger::compare(left, right) > -1; }

    inline friend bool operator <(const ECInteger &left, int value) { return ECInteger::compare(left, value) == -1; }
    inline friend bool operator >(const ECInteger &left, int value) { return ECInteger::compare(left, value) == 1; }
    inline friend bool operator !=(const ECInteger &left, int value) { return ECInteger::compare(left, value) != 0; }
    inline friend bool operator ==(const ECInteger &left, int value) { return ECInteger::compare(left, value) == 0; }
    inline friend bool operator >=(const ECInteger &left, int value) { return ECInteger::compare(left, value) < 1; }
    inline friend bool operator <=(const ECInteger &left, int value) { return ECInteger::compare(left, value) > -1; }
    inline friend bool operator <(const ECInteger &left, uint value) { return ECInteger::compare(left, value) == -1; }
    inline friend bool operator >(const ECInteger &left, uint value) { return ECInteger::compare(left, value) == 1; }
    inline friend bool operator !=(const ECInteger &left, uint value) { return ECInteger::compare(left, value) != 0; }
    inline friend bool operator ==(const ECInteger &left, uint value) { return ECInteger::compare(left, value) == 0; }
    inline friend bool operator >=(const ECInteger &left, uint value) { return ECInteger::compare(left, value) < 1; }
    inline friend bool operator <=(const ECInteger &left, uint value) { return ECInteger::compare(left, value) > -1; }
    inline friend bool operator <(const ECInteger &left, long value) { return ECInteger::compare(left, value) == -1; }
    inline friend bool operator >(const ECInteger &left, long value) { return ECInteger::compare(left, value) == 1; }
    inline friend bool operator !=(const ECInteger &left, long value) { return ECInteger::compare(left, value) != 0; }
    inline friend bool operator ==(const ECInteger &left, long value) { return ECInteger::compare(left, value) == 0; }
    inline friend bool operator >=(const ECInteger &left, long value) { return ECInteger::compare(left, value) < 1; }
    inline friend bool operator <=(const ECInteger &left, long value) { return ECInteger::compare(left, value) > -1; }
    inline friend bool operator <(const ECInteger &left, ulong value) { return ECInteger::compare(left, value) == -1; }
    inline friend bool operator >(const ECInteger &left, ulong value) { return ECInteger::compare(left, value) == 1; }
    inline friend bool operator !=(const ECInteger &left, ulong value) { return ECInteger::compare(left, value) != 0; }
    inline friend bool operator ==(const ECInteger &left, ulong value) { return ECInteger::compare(left, value) == 0; }
    inline friend bool operator >=(const ECInteger &left, ulong value) { return ECInteger::compare(left, value) < 1; }
    inline friend bool operator <=(const ECInteger &left, ulong value) { return ECInteger::compare(left, value) > -1; }
    inline friend bool operator <(const ECInteger &left, const ECInteger &value) { return ECInteger::compare(left, value) == -1; }
    inline friend bool operator >(const ECInteger &left, const ECInteger &value) { return ECInteger::compare(left, value) == 1; }
    inline friend bool operator !=(const ECInteger &left, const ECInteger &value) { return ECInteger::compare(left, value) != 0; }
    inline friend bool operator ==(const ECInteger &left, const ECInteger &value) { return ECInteger::compare(left, value) == 0; }
    inline friend bool operator <=(const ECInteger &left, const ECInteger &value) { return ECInteger::compare(left, value) < 1; }
    inline friend bool operator >=(const ECInteger &left, const ECInteger &value) { return ECInteger::compare(left, value) > -1; }

    operator int() const;
    operator uint() const;
    operator long() const;
    operator ulong() const;
    QString toQString() const;
    QByteArray toQByteArray(bool big_endian = false) const;

    static ECInteger modInverse(const ECInteger &value, const ECInteger &modulus);
    static ECInteger square(const ECInteger &value);
private:
    ECInteger(uint* digits, int length, int sign, bool internal);
};
class ECPoint //Points at Elliptic Curve in Jacobian Space.
{
public:
    ECInteger X;
    ECInteger Y;
    ECInteger Z; //Inverse Modulus Parameter. (If Z = 1, point is in Affine Space.)

    bool isZero() const;

    ECPoint(const ECInteger &x = ECInteger::zero(), const ECInteger &y = ECInteger::zero(), const ECInteger &z = ECInteger::one());

    QString toQString() const;
    ECPoint clone() const;
};
class ECArithmeticsGFp
{
public:
    ECArithmeticsGFp(const QString &urn, bool deterministic = false);
    ECArithmeticsGFp(ECC::CurveName name = ECC::CURVE_SECP256R1, bool deterministic = false);

    ECInteger A;
    ECInteger B;
    ECInteger P;
    ECInteger N;
    ECInteger H;
    ECPoint G;
    int BitLength;
    QString URN;
    bool Deterministic;

    bool checkValidPoint(const ECPoint &P) const;

    //Basic elliptic curve operators
    ECPoint affineDoubling(const ECPoint &P) const; //Tested OK!
    ECPoint affineAddition(const ECPoint &P, const ECPoint &Q) const; //Tested OK!
    ECPoint jacobianDoubling(const ECPoint &P) const; //Tested OK!
    ECPoint jacobianAddition(const ECPoint &P, const ECPoint &Q) const; //Tested OK!
    ECPoint modifiedJacobianDoubling(const ECPoint &P, ECInteger &aZ4) const;

    //Algorithms for doubling and addition.
    ECPoint doubleAndAdd(const ECPoint &P, const ECPoint &Q) const;

    //Signature algorithms
    ECPoint binaryMultiplication(const ECPoint &point, const ECInteger &d) const; //Tested OK!
    ECPoint wNAFMultiplication(const ECPoint &point, const ECInteger &d, const int &w) const; //Tested OK!
    ECPoint fixedBaseMultiplication(const ECPoint &P, const ECInteger &k, const int &w) const; //Tested OK!
    ECPoint fixedBaseMultiplication(const QVector<ECPoint> &preComputes, const ECInteger &k, const int &w) const; //Tested OK!

    //Verify algorithms
    ECPoint shamirsTrick(const ECInteger &u1, const ECPoint &G, const ECInteger &u2, const ECPoint &D) const;
    ECPoint interleavingWithNAF(const ECInteger &u1, const ECPoint &G, const ECInteger &u2, const ECPoint &D) const;
    ECPoint interleavingWithwNAF(const ECInteger &u1, const ECPoint &G, const int &w1, const ECInteger &u2, const ECPoint &D, const int &w2) const;
    ECPoint interleavingWithwNAF(const QVector<int> &u1Naf, const QVector<ECPoint> &precomputesOfG, const QVector<int> &u2Naf, const QVector<ECPoint> &precomputesOfD) const;

    //Signature and verify helpers
    ECInteger calculateAZ4(const ECPoint &P) const;
    QVector<ECPoint> pointPrecomputationsForNAF(const ECPoint &point, const int &w) const;
    QVector<ECPoint> fixedPointCombPreComputes(const ECPoint &point, const int &w) const;

    //Common mathematical operators
    ECInteger modulo(const ECInteger &value) const;
    ECPoint negate(const ECPoint &R) const;

    //Space transformations
    ECPoint jacobianToAffine(const ECPoint &point) const;

    //Random generator
    ECInteger rfc6979(const QByteArray &hash, const ECInteger &x) const;
    ECInteger random(const QByteArray &hash, const ECInteger &x) const;

    //Digital sign
    void sign(const ECInteger &private_key, const ECInteger &e, ECInteger &r, ECInteger &s) const;
    bool verify(const ECPoint &public_key, const ECInteger &e, const ECInteger &r, const ECInteger &s) const;
    bool test(bool show_parameters = false, int test_times = 1, bool generate_pvk_per_test = false) const;

    inline ECPoint doubling(const ECPoint &P) const { return this->jacobianDoubling(P); }
    inline ECPoint addition(const ECPoint &P, const ECPoint &Q) const { return this->jacobianAddition(P, Q); }
    inline ECPoint multiplication(const ECPoint &P, const ECInteger &d) const { return this->wNAFMultiplication(P, d, 4); }
    inline ECPoint multiPointMultiplication(const ECInteger &u1, const ECPoint &G, const ECInteger &u2, const ECPoint &D) const { return this->interleavingWithwNAF(u1, G, 4, u2, D, 4); }
};

struct ECC::pimpl
{
    ECArithmeticsGFp _curve;
    QByteArray _private_key;
    ECPoint _public_key;
    QCryptographicHash::Algorithm _hash_alg;
    int _key_size;
    bool _public_only;
    bool _valid;
};

const QByteArray &ECC::privateKey() const { return this->_pimpl->_private_key; }

int ECC::signatureSize() const { return ((this->_pimpl->_curve.BitLength << 1) + 7) >> 3; }

int ECC::keySize() const { return this->_pimpl->_curve.BitLength; }

QCryptographicHash::Algorithm ECC::hashAlgorithm() const
{
    return this->_pimpl->_hash_alg;
}

void ECC::setHashAlgorithm(QCryptographicHash::Algorithm alg) const
{
    this->_pimpl->_hash_alg = alg;
}

bool ECC::isPrivate() const
{
    return this->_pimpl->_valid && !this->_pimpl->_public_only;
}

bool ECC::isValid() const
{
    return this->_pimpl->_valid;
}

ECC::ECC(const QByteArray &private_key, CurveName name, bool deterministic)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    if(private_key.size() == 0){
        this->_pimpl->_hash_alg = QCryptographicHash::Sha256;
        this->_pimpl->_valid = false;
        return;
    }
    this->_pimpl->_curve = ECArithmeticsGFp(name, deterministic);
    this->_pimpl->_hash_alg = QCryptographicHash::Sha256;
    ECInteger pk(private_key, 1, true);
    this->_pimpl->_private_key = private_key;
    this->_pimpl->_public_key = this->_pimpl->_curve.jacobianToAffine(this->_pimpl->_curve.wNAFMultiplication(this->_pimpl->_curve.G, pk, 4));
    this->_pimpl->_public_only = false;
    this->_pimpl->_valid = true;
}

ECC::ECC(const QString &private_key, ECC::CurveName name, bool deterministic) : ECC(private_key.toUtf8(), name, deterministic)
{

}

QByteArray ECC::signData(const QByteArray &data) const
{
    QCryptographicHash alg(this->_pimpl->_hash_alg);
    alg.addData(data);
    return this->signHash(alg.result());
}

QByteArray ECC::signHash(const QByteArray &hash) const
{
    if(!this->_pimpl->_valid)
        return QByteArray();
    if(this->_pimpl->_public_only)
        return QByteArray();
    if (hash.size() != QCryptographicHash::hashLength(this->_pimpl->_hash_alg))
        return QByteArray();

    ECInteger e(hash, 1, true);
    ECInteger r = ECInteger::zero();
    ECInteger s = ECInteger::zero();

    ECInteger d(this->_pimpl->_private_key, 1, true);

    this->_pimpl->_curve.sign(d, e, r, s);

    int byte_len = (this->_pimpl->_curve.BitLength + 7) >> 3;

    QByteArray rs_pair(byte_len << 1, '\0');
    int r_bytes = r.bytesLength();
    char *r_data = r.bytesData();
    int s_bytes = s.bytesLength();
    char *s_data = s.bytesData();
    char *rs_data = rs_pair.data();
    int skip = byte_len - r.bytesLength();

    for(int i = 0; i < r_bytes; ++i){
        rs_data[i + skip] = r_data[r_bytes - (i + 1)];
    }
    skip = rs_pair.size() - s.bytesLength();
    for(int i = 0; i < s_bytes; ++i){
        rs_data[i + skip] = s_data[s_bytes - (i + 1)];
    }
    return rs_pair;
}

bool ECC::verifyData(const QByteArray &data, const QByteArray &sign) const
{
    QCryptographicHash alg(this->_pimpl->_hash_alg);
    alg.addData(data);
    return this->verifyHash(alg.result(), sign);
}

bool ECC::verifyHash(const QByteArray &hash, const QByteArray &sign) const
{
    if(!this->_pimpl->_valid)
        return false;
    if (hash.size() != QCryptographicHash::hashLength(this->_pimpl->_hash_alg))
        return false;

    ECInteger e(hash, 1, true);

    int pair_length = (this->_pimpl->_curve.BitLength + 7) >> 3;
    if (sign.size() != pair_length * 2)
        return false;

    QByteArray randBytes(pair_length, '\0');
    QByteArray signBytes(pair_length, '\0');

    char *r_data = randBytes.data();
    char *s_data = signBytes.data();
    const char *sign_data = sign.data();
    for(int i = 0; i < pair_length; ++i){
        r_data[pair_length - (i + 1)] = sign_data[i];
    }
    for(int i = 0; i < pair_length; ++i){
        s_data[pair_length - (i + 1)] = sign_data[i + pair_length];
    }

    ECInteger r(randBytes, 1);
    ECInteger s(signBytes, 1);
    if (s.isZero() || r.isZero())
        return false;

    ECInteger w = ECInteger::modInverse(s, this->_pimpl->_curve.N);
    ECInteger u1 = (e * w) % this->_pimpl->_curve.N;
    ECInteger u2 = (r * w) % this->_pimpl->_curve.N;

    ECPoint ss = this->_pimpl->_curve.interleavingWithwNAF(u1, this->_pimpl->_curve.G, 4, u2, this->_pimpl->_public_key, 4);
    ss = this->_pimpl->_curve.jacobianToAffine(ss);
    ECInteger v = ss.X % this->_pimpl->_curve.N;

    return v == r;
}

QString ECC::to4050XmlString() const
{
    if(!this->_pimpl->_valid)
        return QString();
    ECPoint public_key = this->_pimpl->_public_key;
    if (!public_key.Z.isOne())
        public_key = this->_pimpl->_curve.jacobianToAffine(public_key);
    QString xml = QString(
                "<ECCKeyValue xmlns=\"http://www.w3.org/2001/04/xmldsig-more#\">\n"
                "  <DomainParameters>\n"
                "    <NamedCurve URN=\"%1\" />\n"
                "  </DomainParameters>\n"
                "  <PublicKey>\n"
                "    <X Value=\"%2\" xsi:type=\"PrimeFieldElemType\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" />\n"
                "    <Y Value=\"%3\" xsi:type=\"PrimeFieldElemType\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" />\n"
                "  </PublicKey>\n"
                "</ECCKeyValue>").arg(this->_pimpl->_curve.URN, public_key.X.toQString(), public_key.Y.toQString());
    return xml;
}

ECC ECC::from4050XmlString(const QString &rfc4050Xml)
{
    int urn_index_s = rfc4050Xml.indexOf("URN=\"");
    if(urn_index_s == -1) return QByteArray();
    urn_index_s += 5;
    int urn_index_e = rfc4050Xml.indexOf("\"", urn_index_s);
    if(urn_index_e == -1) return QByteArray();
    QString urn = rfc4050Xml.mid(urn_index_s, urn_index_e - urn_index_s);

    int x_index_s = rfc4050Xml.indexOf("X Value=\"");
    if(x_index_s == -1) return QByteArray();
    x_index_s += 9;
    int x_index_e = rfc4050Xml.indexOf("\"", x_index_s);
    if(x_index_e == -1) return QByteArray();
    QString scalar_x_str = rfc4050Xml.mid(x_index_s, x_index_e - x_index_s);
    ECInteger X = ECInteger::parse(scalar_x_str);

    int y_index_s = rfc4050Xml.indexOf("Y Value=\"");
    if(x_index_s == -1) return QByteArray();
    y_index_s += 9;
    int y_index_e = rfc4050Xml.indexOf("\"", y_index_s);
    if(y_index_e == -1) return QByteArray();
    QString scalar_y_str = rfc4050Xml.mid(y_index_s, y_index_e - y_index_s);
    ECInteger Y = ECInteger::parse(scalar_y_str);

    ECC dsa;
    dsa._pimpl = QSharedPointer<pimpl>(new pimpl);
    dsa._pimpl->_curve = ECArithmeticsGFp(urn);
    dsa._pimpl->_hash_alg = QCryptographicHash::Sha256;
    dsa._pimpl->_public_key = ECPoint(X, Y);
    dsa._pimpl->_public_only = true;
    dsa._pimpl->_valid = dsa._pimpl->_curve.checkValidPoint(dsa._pimpl->_public_key);
    return dsa;
}

ECC ECC::withRandomPrivateKey(ECC::CurveName name, bool deterministic)
{
    QByteArray seed = DRBG::fromRandomSeed().generate(32);
    DRBG drbg(seed, 32);
    QByteArray pk = drbg.generate(32);
    return ECC(pk, name, deterministic);
}

ECC ECC::withHexPrivateKey(const QString &hex, ECC::CurveName name, bool deterministic)
{
    ECC dsa;
    dsa._pimpl->_curve = ECArithmeticsGFp(name, deterministic);
    dsa._pimpl->_hash_alg = QCryptographicHash::Sha256;
    ECInteger pk = ECInteger::parseFromHex(hex);
    dsa._pimpl->_private_key = pk.toQByteArray(true);
    dsa._pimpl->_public_key = dsa._pimpl->_curve.jacobianToAffine(dsa._pimpl->_curve.wNAFMultiplication(dsa._pimpl->_curve.G, pk, 4));
    dsa._pimpl->_public_only = false;
    dsa._pimpl->_valid = true;
    return dsa;
}

QByteArray ECC::keyExchange(const QString &other4050PublicKey) const
{
    if(this->_pimpl->_public_only)
        return QByteArray();

    int urn_index_s = other4050PublicKey.indexOf("URN=\"");
    if(urn_index_s == -1) return QByteArray();
    urn_index_s += 5;
    int urn_index_e = other4050PublicKey.indexOf("\"", urn_index_s);
    if(urn_index_e == -1) return QByteArray();
    QString urn = other4050PublicKey.mid(urn_index_s, urn_index_e - urn_index_s);
    if(urn.compare(this->_pimpl->_curve.URN) != 0) return QByteArray();

    int x_index_s = other4050PublicKey.indexOf("X Value=\"");
    if(x_index_s == -1) return QByteArray();
    x_index_s += 9;
    int x_index_e = other4050PublicKey.indexOf("\"", x_index_s);
    if(x_index_e == -1) return QByteArray();
    QString scalar_x_str = other4050PublicKey.mid(x_index_s, x_index_e - x_index_s);
    ECInteger X = ECInteger::parse(scalar_x_str);

    int y_index_s = other4050PublicKey.indexOf("Y Value=\"");
    if(x_index_s == -1) return QByteArray();
    y_index_s += 9;
    int y_index_e = other4050PublicKey.indexOf("\"", y_index_s);
    if(y_index_e == -1) return QByteArray();
    QString scalar_y_str = other4050PublicKey.mid(y_index_s, y_index_e - y_index_s);
    ECInteger Y = ECInteger::parse(scalar_y_str);

    ECPoint public_key = ECPoint(X, Y);
    if(!this->_pimpl->_curve.checkValidPoint(this->_pimpl->_public_key)) return QByteArray();
    ECInteger d(this->_pimpl->_private_key, 1, true);
    ECInteger c = this->_pimpl->_curve.jacobianToAffine(this->_pimpl->_curve.multiplication(public_key, d)).X;

    int byte_length = (this->_pimpl->_curve.BitLength + 7) >> 3;
    QByteArray seed(byte_length, '\0');
    int c_bytes = c.bytesLength();
    char *c_data = c.bytesData();
    char *seed_data = seed.data();
    int skip = byte_length - c_bytes;

    for(int i = 0; i < c_bytes; ++i){
        seed_data[i + skip] = c_data[c_bytes - (i + 1)];
    }
    return seed;
}

////////////////////////////////////////////////////////// SCALAR /////////////////////////////////////////////////////////////////////////////

struct ECIntegerBasicOperators
{
    static uint *add(uint *left, int leftLength, uint *right, int rightLength, int &resultLength)
    {
        uint *operands[2] { left, right };
        int lengths[2] { leftLength, rightLength };
        int lgtr = leftLength < rightLength;

        int max = lengths[lgtr];
        int min = lengths[!lgtr];
        uint *maxOperand = operands[lgtr];
        uint *minOperand = operands[!lgtr];

        uint *result = new uint[max + 1];
        ulong carry = 0;
        for (int i = 0; i < min; ++i){
            ulong sum = (ulong)minOperand[i] + (ulong)maxOperand[i] + carry;
            carry = sum >> 32;
            result[i] = (uint)(sum);
        }

        if (carry > 0){
            for (int i = min; i < max; ++i){
                ulong sum = (ulong)maxOperand[i] + carry;
                carry = sum >> 32;
                result[i] = (uint)(sum);
            }
            result[max] = (uint)(carry);
            resultLength = max + (carry > 0);
        }
        else{
            for (int i = min; i < max; ++i)
                result[i] = maxOperand[i];
            resultLength = max;
        }
        return result;
    }
    static uint *addSingle(uint *left, int leftLength, uint right, int &resultLength)
    {
        ulong sum = (ulong)left[0] + right;
        uint carry = sum >> 32;
        uint* result = new uint[leftLength + 1];
        result[0] = (uint)sum;
        for(int i = 1; i < leftLength; ++i){
            sum = (ulong)carry + left[i];
            result[i] = (uint)sum;
            carry = sum >> 32;
        }
        result[leftLength] = carry;
        resultLength = leftLength + (result[leftLength] != 0);
        return result;
    }
    static uint *divrem(uint *numerator, int numeratorLength, uint *denominator, int denominatorLength, int &quotientLength, int &remainderLength)
    {
        if(denominatorLength == 1){
            remainderLength = 1;
            uint divisor = denominator[0];
            uint *q = new uint[numeratorLength];
            q[numeratorLength - 1] = 0;

            ulong dividend = numerator[numeratorLength - 1];
            int qPos = numeratorLength - 1;
            int rPos = qPos;
            if (dividend >= divisor)
            {
                ulong quot = dividend / divisor;
                q[qPos--] = (uint)quot;
                numerator[rPos] = (uint)(dividend % divisor);
            }
            else
                --qPos;
            --rPos;
            while (rPos > -1)
            {
                int rPosPlusOne = rPos + 1;
                dividend = ((ulong)numerator[rPosPlusOne] << 32) | numerator[rPos];
                ulong quot = dividend / divisor;
                q[qPos--] = (uint)quot;
                numerator[rPosPlusOne] = 0;
                numerator[rPos--] = (uint)(dividend % divisor);
            }
            if (q[numeratorLength - 1] == 0)
                quotientLength = numeratorLength - 1;
            else
                quotientLength = numeratorLength;

            return q;
        } else {
            int numLastU = numeratorLength - 1;
            int opLDiff = numLastU - (denominatorLength - 1);
            quotientLength = opLDiff;
            for (int iu = numLastU; ; --iu)
            {
                if (iu < opLDiff)
                {
                    quotientLength = 1 + quotientLength;
                    break;
                }
                if (denominator[iu - opLDiff] != numerator[iu])
                {
                    if (denominator[iu - opLDiff] < numerator[iu])
                        quotientLength = 1 + quotientLength;
                    break;
                }
            }

            uint *quotient = new uint[quotientLength];

            uint denFirst = denominator[denominatorLength - 1];
            uint denSecond = denominator[denominatorLength - 2];
            int leftShiftBit = ECIntegerBasicOperators::countOfZeroBitStart(denFirst);
            int rightShiftBit = 32 - leftShiftBit;
            if (leftShiftBit > 0)
            {
                denFirst = (denFirst << leftShiftBit) | (denSecond >> rightShiftBit);
                denSecond <<= leftShiftBit;
                if (denominatorLength > 2)
                    denSecond |= denominator[denominatorLength - 3] >> rightShiftBit;
            }

            for (int uInd = quotientLength; --uInd >= 0;)
            {
                uint hiNumDig = (uInd + denominatorLength <= numLastU) ? numerator[uInd + denominatorLength] : 0;

                ulong currNum = ((ulong)hiNumDig << 32) | numerator[uInd + denominatorLength - 1];
                uint nextNum = numerator[uInd + denominatorLength - 2];
                if (leftShiftBit > 0)
                {
                    currNum = (currNum << leftShiftBit) | (nextNum >> rightShiftBit);
                    nextNum <<= leftShiftBit;
                    if (uInd + denominatorLength >= 3)
                        nextNum |= numerator[uInd + denominatorLength - 3] >> rightShiftBit;
                }
                ulong rQuot = currNum / denFirst;
                ulong rRem = (uint)(currNum % denFirst);
                if (rQuot > 0xFFFFFFFF)
                {
                    rRem += denFirst * (rQuot - 0xFFFFFFFF);
                    rQuot = 0xFFFFFFFF;
                }
                while (rRem <= 0xFFFFFFFF && rQuot * denSecond > (((ulong)((uint)rRem) << 32) | nextNum))
                {
                    --rQuot;
                    rRem += denFirst;
                }
                if (rQuot > 0)
                {
                    ulong borrow = 0;
                    for (int u = 0; u < denominatorLength; ++u)
                    {
                        borrow += denominator[u] * rQuot;
                        uint uSub = (uint)borrow;
                        borrow >>= 32;
                        if (numerator[uInd + u] < uSub)
                            ++borrow;
                        numerator[uInd + u] -= uSub;
                    }
                    if (hiNumDig < borrow)
                    {
                        uint uCarry = 0;
                        for (int iu2 = 0; iu2 < denominatorLength; ++iu2)
                        {
                            uCarry = ECIntegerBasicOperators::addCarry(&numerator[uInd + iu2], denominator[iu2], uCarry);
                        }
                        --rQuot;
                    }
                    numLastU = uInd + denominatorLength - 1;
                }
                quotient[uInd] = (uint)rQuot;
            }

            remainderLength = denominatorLength;

            while (numerator[remainderLength - 1] == 0 && remainderLength > 1)
                remainderLength = remainderLength - 1;
            while (quotient[quotientLength - 1] == 0 && quotientLength > 1)
                quotientLength = quotientLength - 1;
            return quotient;
        }
    }
    static void rem(uint *numerator, int numeratorLength, uint *denominator, int denominatorLength, int &remainderLength)
    {
        if(denominatorLength == 1){
            remainderLength = 1;
            uint divisor = denominator[0];

            ulong dividend = numerator[numeratorLength - 1];
            int rPos = numeratorLength - 1;
            if (dividend >= divisor)
                numerator[rPos] = (uint)(dividend % divisor);
            --rPos;
            while (rPos > -1)
            {
                int rPosPlusOne = rPos + 1;
                dividend = ((ulong)numerator[rPosPlusOne] << 32) | numerator[rPos];
                numerator[rPosPlusOne] = 0;
                numerator[rPos--] = (uint)(dividend % divisor);
            }
        } else {
            int numLastU = numeratorLength - 1;
            int opLDiff = numLastU - (denominatorLength - 1);
            int quotientLength = opLDiff;
            for (int iu = numLastU; ; --iu)
            {
                if (iu < opLDiff)
                {
                    quotientLength = 1 + quotientLength;
                    break;
                }
                if (denominator[iu - opLDiff] != numerator[iu])
                {
                    if (denominator[iu - opLDiff] < numerator[iu])
                        quotientLength = 1 + quotientLength;
                    break;
                }
            }

            uint denFirst = denominator[denominatorLength - 1];
            uint denSecond = denominator[denominatorLength - 2];
            int leftShiftBit = ECIntegerBasicOperators::countOfZeroBitStart(denFirst);
            int rightShiftBit = 32 - leftShiftBit;
            if (leftShiftBit > 0)
            {
                denFirst = (denFirst << leftShiftBit) | (denSecond >> rightShiftBit);
                denSecond <<= leftShiftBit;
                if (denominatorLength > 2)
                    denSecond |= denominator[denominatorLength - 3] >> rightShiftBit;
            }

            for (int uInd = quotientLength; --uInd >= 0;)
            {
                uint hiNumDig = (uInd + denominatorLength <= numLastU) ? numerator[uInd + denominatorLength] : 0;

                ulong currNum = ((ulong)hiNumDig << 32) | numerator[uInd + denominatorLength - 1];
                uint nextNum = numerator[uInd + denominatorLength - 2];
                if (leftShiftBit > 0)
                {
                    currNum = (currNum << leftShiftBit) | (nextNum >> rightShiftBit);
                    nextNum <<= leftShiftBit;
                    if (uInd + denominatorLength >= 3)
                        nextNum |= numerator[uInd + denominatorLength - 3] >> rightShiftBit;
                }
                ulong rQuot = currNum / denFirst;
                ulong rRem = (uint)(currNum % denFirst);
                if (rQuot > 0xFFFFFFFF)
                {
                    rRem += denFirst * (rQuot - 0xFFFFFFFF);
                    rQuot = 0xFFFFFFFF;
                }
                while (rRem <= 0xFFFFFFFF && rQuot * denSecond > (((ulong)((uint)rRem) << 32) | nextNum))
                {
                    --rQuot;
                    rRem += denFirst;
                }
                if (rQuot > 0)
                {
                    ulong borrow = 0;
                    for (int u = 0; u < denominatorLength; ++u)
                    {
                        borrow += denominator[u] * rQuot;
                        uint uSub = (uint)borrow;
                        borrow >>= 32;
                        if (numerator[uInd + u] < uSub)
                            ++borrow;
                        numerator[uInd + u] -= uSub;
                    }
                    if (hiNumDig < borrow)
                    {
                        uint uCarry = 0;
                        for (int iu2 = 0; iu2 < denominatorLength; ++iu2)
                        {
                            uCarry = ECIntegerBasicOperators::addCarry(&numerator[uInd + iu2], denominator[iu2], uCarry);
                        }
                        --rQuot;
                    }
                    numLastU = uInd + denominatorLength - 1;
                }
            }
            remainderLength = denominatorLength;
            while (numerator[remainderLength - 1] == 0 && remainderLength > 1)
                remainderLength = remainderLength - 1;
        }
    }
    static uint *mul(uint *left, int leftLength, uint *right, int rightLength, int &resultLength)
    {
        if (leftLength > rightLength)
        {
            int tmp = leftLength;
            leftLength = rightLength;
            rightLength = tmp;
            uint *tmpb = left;
            left = right;
            right = tmpb;
        }

        resultLength = leftLength + rightLength;
        uint *result = new uint[resultLength];

        for(int i = 0; i < resultLength; ++i)
            result[i] = 0;

        for (int i = 0; i < leftLength; ++i)
        {
            if (left[i] == 0) continue;

            ulong carry = 0;
            for (int j = 0, k = i; j < rightLength; ++j, ++k)
            {
                ulong val = ((ulong)left[i] * right[j]) + result[k] + carry;
                result[k] = (uint)val;
                carry = (val >> 32);
            }
            result[i + rightLength] = (uint)carry;
        }
        while (result[resultLength - 1] == 0 && resultLength > 1)
            resultLength = resultLength - 1;
        return result;
    }
    static uint *mulSingle(uint *left, int leftLength, uint right, int &resultLength)
    {
        resultLength = leftLength + 1;
        uint *result = new uint[resultLength];

        result[0] = 0;
        ulong carry;
        for (int i = 0; i < leftLength; ++i)
        {
            carry = 0;
            ulong val = ((ulong)left[i] * (ulong)right) + (ulong)result[i];
            result[i] = (uint)val;
            carry = (val >> 32);
            result[i + 1] = (uint)carry;
        }

        while (result[resultLength - 1] == 0 && resultLength > 1)
            resultLength = resultLength - 1;
        return result;
    }
    static uint *sub(uint *left, int leftLength, uint *right, int rightLength, int &resultLength)
    {
        uint *result = new uint[leftLength];
        for(int i = leftLength - rightLength; i < leftLength; ++i)
            result[i] = 0;

        int carry = 0;
        int i = 0;
        long diff;
        for ( ; i < rightLength; ++i)
        {
            diff = (long)left[i] - (long)right[i] + carry;
            result[i] = (uint)(diff);
            carry = (diff >> 63);
        }
        for ( ; carry && i < leftLength; ++i)
        {
            diff = (long)left[i] + carry;
            result[i] = (uint)(diff);
            carry = (diff >> 63);
        }
        for ( ; i < leftLength; ++i)
            result[i] = left[i];

        resultLength = leftLength;
        while (result[resultLength - 1] == 0 && resultLength > 1)
            resultLength = resultLength - 1;
        return result;
    }

    static uint *shiftRight(uint *digits, int digitLength, int shift, int &resultLength)
    {
        if (shift == 0) {
            uint *clone = new uint[digitLength];
            for(int i = 0; i < digitLength; ++i)
                clone[i] = digits[i];
            return clone;
        }

        int fullShift = shift >> 5;
        int remShift = shift & 31;

        int predictedLen = (digitLength) - fullShift;
        uint *result = new uint[predictedLen];
        for(int i = 0; i < predictedLen; ++i)
            result[i] = digits[fullShift + i];
        if(remShift > 0){
            result[0] = result[0] >> remShift;
            for(int i = 1; i < predictedLen; ++i){
                result[i - 1] |= result[i] << (32 - remShift);
                result[i] = result[i] >> remShift;
            }
        }
        if(result[predictedLen - 1] == 0 && predictedLen > 1)
            --predictedLen;
        resultLength = predictedLen;
        return result;
    }
    static uint *shiftLeft(uint *digits, int digitLength, int shift, int &resultLength)
    {
        if (shift == 0) {
            uint *clone = new uint[digitLength];
            for(int i = 0; i < digitLength; ++i)
                clone[i] = digits[i];
            return clone;
        }

        int fullShift = shift >> 5;
        int remShift = shift & 31;
        int needRemShift = remShift > 0;
        resultLength = digitLength + fullShift + needRemShift;
        uint *result = new uint[resultLength];
        result[resultLength - 1] = 0;

        for(int i = 0; i < digitLength; ++i)
            result[i + fullShift] = digits[i];
        if(remShift > 0){
            for(int i = resultLength - 1; i > fullShift; --i){
                uint dig = result[i] << remShift;
                dig |= result[i - 1] >> (32 - remShift);
                result[i] = dig;
            }
            result[fullShift] = result[fullShift] << remShift;
        }
        for(int i = 0; i < fullShift; ++i)
            result[i] = 0;
        if(result[resultLength - 1] == 0 && resultLength > 1)
            --resultLength;

        return result;
    }
    static int compare(uint *left, int leftLength, uint *right, int rightLength)
    {
        int c = (int)(leftLength > rightLength);
        c = -(int)(leftLength < rightLength) * ((c + 1) & 1) + c;
        for(int i = leftLength - 1; !c && (i >= 0); --i)
            c = (int)(left[i] > right[i]) - (int)(left[i] < right[i]);
        return c;
    }
    static QString toQString(uint *digits, int digitLength, int sign)
    {
        if (sign == 0 || digitLength == 0) {
            return "0";
        }
        else if (digitLength == 1 && sign == 1){
            char *str = new char[20];
            sprintf(str, "%d", digits[0]);
            QString u16str = str;
            delete[] str;
            return u16str;
        }

        const uint kuBase = 1000000000; // 10^9
        int cuMax = digitLength * 10 / 9 + 2;
        uint *rguDst = new uint[cuMax];
        int cuDst = 0;
        for(int i = 0; i < cuMax; ++i)
            rguDst[i] = 0;

        for (int iuSrc = digitLength; --iuSrc >= 0;){
            uint uCarry = digits[iuSrc];
            for (int iuDst = 0; iuDst < cuDst; ++iuDst){
                ulong uuRes = ((ulong)rguDst[iuDst] << 32) | uCarry;
                rguDst[iuDst] = (uint)(uuRes % kuBase);
                uCarry = (uint)(uuRes / kuBase);
            }
            if (uCarry != 0){
                rguDst[cuDst++] = uCarry % kuBase;
                uCarry /= kuBase;
                if (uCarry != 0)
                    rguDst[cuDst++] = uCarry;
            }
        }
        int cchMax = cuDst * 9;
        int rgchBufSize = cchMax + 2 + (sign == -1);
        int ichDst = cchMax;

        std::shared_ptr<char[]> rgchRef(new char[rgchBufSize]);
        char *rgch = rgchRef.get();

        for (int iuDst = 0; iuDst < cuDst - 1; ++iuDst){
            uint uDig = rguDst[iuDst];
            for (int cch = 9; --cch >= 0; ){
                int ascii = (48 + uDig % 10);
                rgch[--ichDst] = (char)ascii;
                uDig /= 10;
            }
        }
        for (uint uDig = rguDst[cuDst - 1]; uDig != 0; ){
            int ascii = (48 + uDig % 10);
            rgch[--ichDst] = (char)ascii;
            uDig /= 10;
        }
        delete[] rguDst;
        if (sign == -1){
            rgch[--ichDst] = '-';
        }
        rgch += ichDst;
        rgch[cchMax - ichDst] = '\0';
        return QString(rgch);
    }

    static uint *unsignedParse(char *value, int charLen, int &digitLength)
    {
        int offset = charLen & 7;
        int base108Len = (charLen >> 3);
        uint lastDigit = 0;

        ++base108Len;
        for(int i = 0; i < offset; ++i){
            lastDigit *= 10;
            lastDigit += value[i] - 48;
        }
        uint *base108Digits = new uint[base108Len];
        int uiLast = base108Len - 1;
        base108Digits[uiLast] = lastDigit;
        for(int i = uiLast - 1; i >= 0; --i){
            uint curDigit = 0;
            offset += 8;
            for(int j = offset - 8; j < offset; ++j){
                curDigit *= 10;
                curDigit += value[j] - 48;
            }
            base108Digits[i] = curDigit;
        }

        const uint cBase = 100000000u;
        uint *digits = new uint[1];
        digits[0] = 0;
        int resultLength = 1;
        uint *tmp = digits;
        digits = ECIntegerBasicOperators::addSingle(digits, resultLength, base108Digits[base108Len - 1], resultLength);
        delete[] tmp;
        for(int i = base108Len - 2; i >= 0; --i){
            tmp = digits;
            digits = ECIntegerBasicOperators::mulSingle(digits, resultLength, cBase, resultLength);
            delete[] tmp;
            tmp = digits;
            uint base108dig = base108Digits[i];
            digits = ECIntegerBasicOperators::addSingle(digits, resultLength, base108dig, resultLength);
            delete[] tmp;
        }
        delete[] base108Digits;
        digitLength = resultLength;
        return digits;
    }
    static long unsignedBitsLength(uint *digits, int digitLength)
    {
        uint uiLast = digits[digitLength - 1];
        return 32 * (long)digitLength - ECIntegerBasicOperators::countOfZeroBitStart(uiLast);
    }

    static uint addCarry(uint *u1, uint u2, uint uCarry)
    {
        ulong uu = (ulong)*u1 + u2 + uCarry;
        *u1 = (uint)uu;
        return (uint)(uu >> 32);
    }
    static int countOfZeroBitStart(uint u)
    {
        int cbit = (u == 0);
        int f = (u & 0xFFFF0000) == 0;
        cbit += f << 4;
        f = ((u << cbit) & 0xFF000000) == 0;
        cbit += f << 3;
        f = ((u << cbit) & 0xF0000000) == 0;
        cbit += f << 2;
        f = ((u << cbit) & 0xC0000000) == 0;
        cbit += f << 1;
        f = ((u << cbit) & 0x80000000) == 0;
        cbit += f;
        return cbit;
    }
    static int getBit(uint *digits, int digitLength, long bitPosition) //Tested OK.
    {
        int digitPos = (int)(bitPosition / 32);
        if (digitLength <= digitPos)
            return 0;

        int smallBitPos = (int)(bitPosition & 31);
        return (int)((digits[digitPos] >> smallBitPos) & 1);
    }

    static long signedBitsLength(uint *digits, int digitLength, int sign) //Tested OK.
    {
        if (sign == 0)
            return 1;
        if (digitLength == 1 && digits[0] == 0)
            return 1;

        uint lastDigit = digits[digitLength - 1];
        unsigned char lastByte = 0;
        int bitsLength = digitLength * 32;

        if ((lastByte = (unsigned char)(lastDigit >> 24)) != 0) { }
        else if ((lastByte = (unsigned char)(lastDigit >> 16)) != 0) { bitsLength -= 8; }
        else if ((lastByte = (unsigned char)(lastDigit >> 8)) != 0) { bitsLength -= 16; }
        else if ((lastByte = (unsigned char)(lastDigit)) != 0) { bitsLength -= 24; }

        if ((lastByte >> 7) == 1 && sign == -1)
            bitsLength += 8;
        return bitsLength;
    }

    static uint *fromUnsignedBytes(unsigned char *data, int data_length, bool bigEndian, int &digitLength) //Tested OK.
    {
        digitLength = data_length/ 4;
        if ((data_length & 3) > 0)
            ++digitLength;

        uint *digits = new uint[digitLength];

        if (bigEndian)
        {
            int digitPos = digitLength - 1;
            int dataPos = 0;

            int nullDataLength = data_length & 3;
            if (nullDataLength == 1)
            {
                digits[digitPos--] = data[dataPos++];
            }
            else if (nullDataLength == 2)
            {
                uint digit = 0;
                digit |= (uint)(data[dataPos++] << 8);
                digit |= (uint)(data[dataPos++]);
                digits[digitPos--] = digit;
            }
            else if (nullDataLength == 3)
            {
                uint digit = 0;
                digit |= (uint)(data[dataPos++] << 16);
                digit |= (uint)(data[dataPos++] << 8);
                digit |= (uint)(data[dataPos++]);
                digits[digitPos--] = digit;
            }

            while (digitPos > -1)
            {
                uint current = 0;
                current |= (uint)(data[dataPos++] << 24);
                current |= (uint)(data[dataPos++] << 16);
                current |= (uint)(data[dataPos++] << 8);
                current |= (uint)(data[dataPos++]);
                digits[digitPos--] = current;
            }
        }
        else
        {
            int digitPos = 0;
            int dataPos = 0;
            int lastDigitPos = digitLength - 1;
            while (digitPos < lastDigitPos)
            {
                uint current = 0;
                current |= (uint)(data[dataPos++]);
                current |= (uint)(data[dataPos++] << 8);
                current |= (uint)(data[dataPos++] << 16);
                current |= (uint)(data[dataPos++] << 24);
                digits[digitPos++] = current;
            }

            int nullDataLength = data_length & 3;

            if (nullDataLength == 1)
            {
                digits[lastDigitPos] = data[dataPos++];
            }
            else if (nullDataLength == 2)
            {
                uint digit = 0;
                digit |= (uint)(data[dataPos++]);
                digit |= (uint)(data[dataPos++] << 8);
                digits[lastDigitPos] = digit;
            }
            else if (nullDataLength == 3)
            {
                uint digit = 0;
                digit |= (uint)(data[dataPos++]);
                digit |= (uint)(data[dataPos++] << 8);
                digit |= (uint)(data[dataPos++] << 16);
                digits[lastDigitPos] = digit;
            }
            else if (nullDataLength == 0)
            {
                uint digit = 0;
                digit |= (uint)(data[dataPos++]);
                digit |= (uint)(data[dataPos++] << 8);
                digit |= (uint)(data[dataPos++] << 16);
                digit |= (uint)(data[dataPos++] << 24);
                digits[lastDigitPos] = digit;
            }
        }
        ECIntegerBasicOperators::trim(digits, digitLength);
        return digits;
    }

    static void trim(uint *digits, int &digitLength)
    {
        while (digits[digitLength - 1] == 0 && digitLength > 1)
            --digitLength;
    }
};

struct ECInteger::pimpl
{
    int _digit_length;
    uint *_digits;
    int _sign;
    bool _weak = false;

    ~pimpl()
    {
        if(this->_weak)
            return;
        delete[] this->_digits;
    }
};

ECInteger::ECInteger()
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_sign = 0;
    this->_pimpl->_digits = new uint[1];
    this->_pimpl->_digits[0] = 0;
    this->_pimpl->_digit_length = 1;
}
ECInteger::ECInteger(int value)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_sign = (value >> 31);
    this->_pimpl->_sign = this->_pimpl->_sign + (int)(value > 0);
    value *= this->_pimpl->_sign;
    this->_pimpl->_digit_length = 1;
    this->_pimpl->_digits = new uint[1];
    this->_pimpl->_digits[0] = (uint)value;
}
ECInteger::ECInteger(uint value)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_sign = value > 0;
    this->_pimpl->_digit_length = 1;
    this->_pimpl->_digits = new uint[1];
    this->_pimpl->_digits[0] = (uint)value;
}
ECInteger::ECInteger(long value)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_sign = (value >> 63);
    this->_pimpl->_sign = this->_pimpl->_sign + (int)(value > 0);
    value *= this->_pimpl->_sign;
    int vgtuim = (int)(value > 0xffffffff);
    this->_pimpl->_digit_length = 1 + vgtuim;
    this->_pimpl->_digits = new uint[this->_pimpl->_digit_length];
    this->_pimpl->_digits[vgtuim] = (uint)(value >> 32);
    this->_pimpl->_digits[0] = (uint)value;
}
ECInteger::ECInteger(ulong value)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_sign = value > 0;
    int vgtuim = (int)(value > 0xffffffff);
    this->_pimpl->_digit_length = 1 + vgtuim;
    this->_pimpl->_digits = new uint[this->_pimpl->_digit_length];
    this->_pimpl->_digits[vgtuim] = (uint)(value >> 32);
    this->_pimpl->_digits[0] = (uint)value;
}

ECInteger::ECInteger(char *bytes, long bytes_length, int sign, bool big_endian)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_digits = ECIntegerBasicOperators::fromUnsignedBytes(reinterpret_cast<unsigned char*>(bytes), bytes_length, big_endian, this->_pimpl->_digit_length);
    this->_pimpl->_sign = sign;
}

ECInteger::ECInteger(const QByteArray &bytes, int sign, bool big_endian)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_digits = ECIntegerBasicOperators::fromUnsignedBytes(reinterpret_cast<unsigned char*>(const_cast<char*>(bytes.data())), bytes.size(), big_endian, this->_pimpl->_digit_length);
    this->_pimpl->_sign = sign;
}

bool ECInteger::isZero() const { return this->_pimpl->_sign == 0; }
bool ECInteger::isOne() const { return this->_pimpl->_digit_length == 1 && this->_pimpl->_digits[0] == 1 && this->_pimpl->_sign == 1; }
bool ECInteger::isNegative() const { return this->_pimpl->_sign == -1; }
bool ECInteger::isPositive() const { return this->_pimpl->_sign == 1; }
bool ECInteger::isEven() const { return (this->_pimpl->_digits[0] & 1) == 0; }
bool ECInteger::isOdd() const { return (this->_pimpl->_digits[0] & 1); }
int ECInteger::sign() const { return this->_pimpl->_sign; }
int ECInteger::digitLength() const { return this->_pimpl->_digit_length; }

long ECInteger::bytesLength() const
{
    long bitlen = this->bitsLength();
    return (bitlen >> 3) + (int)((bitlen & 7) > 0);
}
long ECInteger::bitsLength() const { return ECIntegerBasicOperators::signedBitsLength(this->_pimpl->_digits, this->_pimpl->_digit_length, this->_pimpl->_sign); }
uint ECInteger::firstDigit() const { return this->_pimpl->_digits[0]; }
uint *ECInteger::data() const { return this->_pimpl->_digits; }

char *ECInteger::bytesData() const
{
    return reinterpret_cast<char *>(this->_pimpl->_digits);
}

ECInteger &ECInteger::add(const ECInteger &value)
{
    if(this->_pimpl->_sign == value._pimpl->_sign){
        if(this->_pimpl->_sign == 0){
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = new uint[1] { 0 };
            return *this;
        }
        uint *digits = ECIntegerBasicOperators::add(this->_pimpl->_digits, this->_pimpl->_digit_length, value._pimpl->_digits, value._pimpl->_digit_length, this->_pimpl->_digit_length);
        delete[] this->_pimpl->_digits;
        this->_pimpl->_digits = digits;
        return *this;
    } else {
        int c = ECIntegerBasicOperators::compare(this->_pimpl->_digits, this->_pimpl->_digit_length, value._pimpl->_digits, value._pimpl->_digit_length);
        uint *digits;
        if(c == 1){
            digits = ECIntegerBasicOperators::sub(this->_pimpl->_digits, this->_pimpl->_digit_length, value._pimpl->_digits, value._pimpl->_digit_length, this->_pimpl->_digit_length);
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = digits;
        } else if(c == -1){
            digits = ECIntegerBasicOperators::sub(value._pimpl->_digits, value._pimpl->_digit_length, this->_pimpl->_digits, this->_pimpl->_digit_length, this->_pimpl->_digit_length);
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = digits;
            this->_pimpl->_sign = value._pimpl->_sign;
        } else {
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = new uint[1] { 0 };
            this->_pimpl->_digit_length = 1;
            this->_pimpl->_sign = 0;
        }
        return *this;
    }
}
ECInteger &ECInteger::sub(const ECInteger &value)
{
    if(this->_pimpl->_sign == -value._pimpl->_sign){
        if(this->_pimpl->_sign == 0){
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = new uint[1] { 0 };
            return *this;
        }
        uint *digits = ECIntegerBasicOperators::add(this->_pimpl->_digits, this->_pimpl->_digit_length, value._pimpl->_digits, value._pimpl->_digit_length, this->_pimpl->_digit_length);
        delete[] this->_pimpl->_digits;
        this->_pimpl->_digits = digits;
        return *this;
    } else {
        int c = ECIntegerBasicOperators::compare(this->_pimpl->_digits, this->_pimpl->_digit_length, value._pimpl->_digits, value._pimpl->_digit_length);
        uint *digits;
        if(c == 1){
            digits = ECIntegerBasicOperators::sub(this->_pimpl->_digits, this->_pimpl->_digit_length, value._pimpl->_digits, value._pimpl->_digit_length, this->_pimpl->_digit_length);
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = digits;
        } else if(c == -1){
            digits = ECIntegerBasicOperators::sub(value._pimpl->_digits, value._pimpl->_digit_length, this->_pimpl->_digits, this->_pimpl->_digit_length, this->_pimpl->_digit_length);
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = digits;
            this->_pimpl->_sign = -value._pimpl->_sign;
        } else {
            delete[] this->_pimpl->_digits;
            this->_pimpl->_digits = new uint[1] { 0 };
            this->_pimpl->_digit_length = 1;
            this->_pimpl->_sign = 0;
        }
        return *this;
    }
}
ECInteger &ECInteger::mul(const ECInteger &value)
{
    this->_pimpl->_sign = this->_pimpl->_sign * value._pimpl->_sign;
    if(this->_pimpl->_sign == 0){
        delete[] this->_pimpl->_digits;
        this->_pimpl->_digits = new uint[1] { 0 };
        this->_pimpl->_digit_length = 1;
        return *this;
    }
    uint *digits = ECIntegerBasicOperators::mul(this->_pimpl->_digits, this->_pimpl->_digit_length, value._pimpl->_digits, value._pimpl->_digit_length, this->_pimpl->_digit_length);
    delete[] this->_pimpl->_digits;
    this->_pimpl->_digits = digits;
    return *this;
}
ECInteger &ECInteger::div(const ECInteger &divisor)
{
    if(divisor.isZero())
        throw std::runtime_error("Cannot divide a number by zero.");
    ECInteger rem;
    return this->divrem(divisor, rem);
}
ECInteger &ECInteger::rem(const ECInteger &modulus)
{
    if(modulus.isZero())
        throw std::runtime_error("Cannot divide a number by zero.");
    if(this->_pimpl->_sign == 0)
        return *this;
    this->_pimpl->_sign = this->_pimpl->_sign * modulus._pimpl->_sign;
    if(this->_pimpl->_digit_length >= modulus._pimpl->_digit_length)
        ECIntegerBasicOperators::rem(this->_pimpl->_digits, this->_pimpl->_digit_length, modulus._pimpl->_digits, modulus._pimpl->_digit_length, this->_pimpl->_digit_length);
    return *this;
}
ECInteger &ECInteger::divrem(const ECInteger &divisor, ECInteger &remainder)
{
    if(divisor._pimpl->_sign == 0)
        throw std::runtime_error("Cannot divide a number by zero.");
    if(this->_pimpl->_sign == 0){
        if(this->_pimpl->_digits != remainder._pimpl->_digits){
            delete[] remainder._pimpl->_digits;
            remainder._pimpl->_digits = new uint[1] { 0 };
            remainder._pimpl->_digit_length = 1;
            remainder._pimpl->_sign = 0;
        }
        return *this;
    } else {
        this->_pimpl->_sign = this->_pimpl->_sign * divisor._pimpl->_sign;
        remainder._pimpl->_sign = this->_pimpl->_sign;
        int c = ECIntegerBasicOperators::compare(this->_pimpl->_digits, this->_pimpl->_digit_length, divisor._pimpl->_digits, divisor._pimpl->_digit_length);
        if(c == -1){
            if(this->_pimpl->_digits != remainder._pimpl->_digits){
                delete[] remainder._pimpl->_digits;
                remainder._pimpl->_digits = this->_pimpl->_digits;
                remainder._pimpl->_digit_length = this->_pimpl->_digit_length;
                this->_pimpl->_digits = new uint[1] { 0 };
                this->_pimpl->_digit_length = 1;
                this->_pimpl->_sign = 0;
            }
            return *this;
        } else if (c == 0){
            if(this->_pimpl->_digits == remainder._pimpl->_digits){
                delete[] this->_pimpl->_digits;
                this->_pimpl->_digits = new uint[1] { 0 };
                this->_pimpl->_digit_length = 1;
            } else {
                delete[] this->_pimpl->_digits;
                this->_pimpl->_digits = new uint[1] { 1 };
                this->_pimpl->_digit_length = 1;
                delete[] remainder._pimpl->_digits;
                remainder._pimpl->_digits = new uint[1] { 0 };
                remainder._pimpl->_digit_length = 1;
                remainder._pimpl->_sign = 0;
            }
            return *this;
        }else {
            int quotientLength, remainderLength;
            uint *quot = ECIntegerBasicOperators::divrem(this->_pimpl->_digits, this->_pimpl->_digit_length, divisor._pimpl->_digits, divisor._pimpl->_digit_length, quotientLength, remainderLength);
            if(this->_pimpl->_digits == remainder._pimpl->_digits){
                delete[] quot;
                this->_pimpl->_digit_length = remainderLength;
                return *this;
            } else {
                delete[] remainder._pimpl->_digits;
                remainder._pimpl->_digits = this->_pimpl->_digits;
                remainder._pimpl->_digit_length = remainderLength;
                this->_pimpl->_digits = quot;
                this->_pimpl->_digit_length = quotientLength;
                remainder._pimpl->_sign = (!(remainder._pimpl->_digit_length == 1 && !remainder._pimpl->_digits[0])) * remainder._pimpl->_sign;
            }
            return *this;
        }
    }
}

ECInteger ECInteger::add(const ECInteger &left, const ECInteger &right)
{
    if(left._pimpl->_sign == right._pimpl->_sign){
        if(left._pimpl->_sign == 0){
            uint *digits = new uint[1] { 0 };
            return ECInteger(digits, 1, 0, true);
        }
        int resultLength;
        uint *digits = ECIntegerBasicOperators::add(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length, resultLength);
        return ECInteger(digits, resultLength, left._pimpl->_sign, resultLength);
    } else {
        int c = ECIntegerBasicOperators::compare(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length);
        if(c == 1){
            int resultLength;
            uint *digits = ECIntegerBasicOperators::sub(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length, resultLength);
            return ECInteger(digits, resultLength, left._pimpl->_sign, true);
        } else if(c == -1){
            int resultLength;
            uint *digits = ECIntegerBasicOperators::sub(right._pimpl->_digits, right._pimpl->_digit_length, left._pimpl->_digits, left._pimpl->_digit_length, resultLength);
            return ECInteger(digits, resultLength, right._pimpl->_sign, true);
        } else {
            uint *digits = new uint[1] { 0 };
            return ECInteger(digits, 1, 0, true);
        }
    }
}
ECInteger ECInteger::sub(const ECInteger &left, const ECInteger &right)
{
    if(left._pimpl->_sign == -right._pimpl->_sign){
        if(left._pimpl->_sign == 0){
            return ECInteger(0u);
        }
        int resultLength;
        uint *digits = ECIntegerBasicOperators::add(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length, resultLength);
        return ECInteger(digits, resultLength, left._pimpl->_sign, true);
    } else {
        int c = ECIntegerBasicOperators::compare(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length);
        if(c == 1){
            int resultLength;
            uint *digits = ECIntegerBasicOperators::sub(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length, resultLength);
            return ECInteger(digits, resultLength, left._pimpl->_sign, true);
        } else if(c == -1){
            int resultLength;
            uint *digits = ECIntegerBasicOperators::sub(right._pimpl->_digits, right._pimpl->_digit_length, left._pimpl->_digits, left._pimpl->_digit_length, resultLength);
            return ECInteger(digits, resultLength, -right._pimpl->_sign, true);
        } else {
            return ECInteger(0u);
        }
    }
}
ECInteger ECInteger::mul(const ECInteger &left, const ECInteger &right)
{
    int result_sign = left._pimpl->_sign * right._pimpl->_sign;
    if(result_sign == 0)
        return ECInteger(0u);

    int resultLength;
    uint *digits = ECIntegerBasicOperators::mul(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length, resultLength);
    return ECInteger(digits, resultLength, result_sign, true);
}
ECInteger ECInteger::div(const ECInteger &dividend, const ECInteger &divisor)
{
    if(divisor._pimpl->_sign == 0)
        throw std::runtime_error("Cannot divide a number by zero.");
    if(dividend._pimpl->_sign == 0){
        return ECInteger(0u);
    } else {
        int c = ECIntegerBasicOperators::compare(dividend._pimpl->_digits, dividend._pimpl->_digit_length, divisor._pimpl->_digits, divisor._pimpl->_digit_length);
        int result_sign = dividend._pimpl->_sign * divisor._pimpl->_sign;
        if(c == -1)
            return ECInteger(0u);
        else if (c == 0)
            return ECInteger(result_sign);
        else {
            int quotientLength, remainderLength;
            uint *remainder = new uint[dividend._pimpl->_digit_length];
            for(int i = 0; i < dividend._pimpl->_digit_length; ++i)
                remainder[i] = dividend._pimpl->_digits[i];
            uint *quot = ECIntegerBasicOperators::divrem(remainder, dividend._pimpl->_digit_length, divisor._pimpl->_digits, divisor._pimpl->_digit_length, quotientLength, remainderLength);
            delete[] remainder;
            return ECInteger(quot, quotientLength, result_sign, true);
        }
    }
}
ECInteger ECInteger::rem(const ECInteger &dividend, const ECInteger &divisor)
{
    if(divisor.isZero())
        throw std::runtime_error("Cannot divide a number by zero.");
    if(dividend._pimpl->_sign == 0)
        return ECInteger(0u);
    if(dividend._pimpl->_digit_length >= divisor._pimpl->_digit_length){
        uint *remainder = new uint[dividend._pimpl->_digit_length];
        for(int i = 0; i < dividend._pimpl->_digit_length; ++i)
            remainder[i] = dividend._pimpl->_digits[i];
        int remainderLength;
        ECIntegerBasicOperators::rem(remainder, dividend._pimpl->_digit_length, divisor._pimpl->_digits, divisor._pimpl->_digit_length, remainderLength);
        return ECInteger(remainder, remainderLength, dividend._pimpl->_sign * divisor._pimpl->_sign, true);
    } else {
        ECInteger rem = dividend.clone();
        rem._pimpl->_sign *= divisor._pimpl->_sign;
        return rem;
    }
}
ECInteger ECInteger::divrem(const ECInteger &dividend, const ECInteger &divisor, ECInteger &remainder)
{
    if(dividend._pimpl->_digits == remainder._pimpl->_digits)
        return dividend.clone().divrem(divisor, remainder);
    if(divisor._pimpl->_sign == 0)
        throw std::runtime_error("Cannot divide a number by zero.");
    if(dividend._pimpl->_sign == 0){
        return ECInteger(0u);
    } else {
        int result_sign = dividend._pimpl->_sign * divisor._pimpl->_sign;
        remainder._pimpl->_sign = result_sign;
        delete[] remainder._pimpl->_digits;
        remainder._pimpl->_digits = new uint[dividend._pimpl->_digit_length];
        for(int i = 0; i < dividend._pimpl->_digit_length; ++i)
            remainder._pimpl->_digits[i] = dividend._pimpl->_digits[i];
        if(dividend._pimpl->_digit_length >= divisor._pimpl->_digit_length) {
            int quotientLength;
            uint *quot = ECIntegerBasicOperators::divrem(remainder._pimpl->_digits, dividend._pimpl->_digit_length, divisor._pimpl->_digits, divisor._pimpl->_digit_length, quotientLength, remainder._pimpl->_digit_length);
            return ECInteger(quot, quotientLength, result_sign, true);
        } else {
            remainder._pimpl->_digit_length = dividend._pimpl->_digit_length;
            return ECInteger(0u);
        }
    }
}

ECInteger &ECInteger::bitshift(const int &shift)
{
    uint *digits;
    if(shift > 0)
        digits = ECIntegerBasicOperators::shiftLeft(this->_pimpl->_digits, this->_pimpl->_digit_length, shift, this->_pimpl->_digit_length);
    else
        digits = ECIntegerBasicOperators::shiftRight(this->_pimpl->_digits, this->_pimpl->_digit_length, -shift, this->_pimpl->_digit_length);
    delete[] this->_pimpl->_digits;
    this->_pimpl->_digits = digits;
    return *this;
}

ECInteger &ECInteger::rightShift(const int &shift)
{
    return this->bitshift(-shift);
}

ECInteger &ECInteger::leftShift(const int &shift)
{
    return this->bitshift(shift);
}

ECInteger &ECInteger::negate()
{
    this->_pimpl->_sign *= -1;
    return *this;
}
ECInteger &ECInteger::square()
{
    return this->mul(*this);
}

ECInteger &ECInteger::cube()
{
    ECInteger sq = this->clone().mul(*this);
    return this->mul(sq);
}
ECInteger &ECInteger::abs()
{
    this->_pimpl->_sign *= this->_pimpl->_sign;
    return *this;
}
ECInteger &ECInteger::pow(uint exponent)
{
    if (exponent == 1)
        return *this;
    if (exponent == 0){
        delete[] this->_pimpl->_digits;
        this->_pimpl->_digits = new uint[1] { 1 };
        this->_pimpl->_digit_length = 1;
        this->_pimpl->_sign = 1;
    }
    ECInteger value = this->clone();
    if (!(exponent & 1)){
        delete[] this->_pimpl->_digits;
        this->_pimpl->_digits = new uint[1] { 1 };
        this->_pimpl->_digit_length = 1;
        this->_pimpl->_sign = 1;
    }

    exponent >>= 1;
    while (exponent != 0)
    {
        value.square();
        if ((exponent & 1) == 1)
            this->mul(value);
        exponent >>= 1;
    }
    return *this;
}

int ECInteger::bit(const long &pos) const
{
    if (this->_pimpl->_sign == 0)
        return 0;
    if (pos > this->bitsLength())
        return 0;
    int bit = ECIntegerBasicOperators::getBit(this->_pimpl->_digits, this->_pimpl->_digit_length, pos);
    if (this->_pimpl->_sign == 1)
        return bit;
    else
        return ~bit;
}

QString ECInteger::toQString() const
{
    if(this->_pimpl->_digit_length == 1){
        char buffer[50];
        int len = sprintf(&buffer[1], "%u", this->_pimpl->_digits[0]);
        buffer[len + 1] = 0;
        buffer[0] = '-';
        return QString((const char *)&buffer[(this->_pimpl->_sign + 2) >> 1]);
    } else {
        return ECIntegerBasicOperators::toQString(this->_pimpl->_digits, this->_pimpl->_digit_length, this->_pimpl->_sign);
    }
}

QByteArray ECInteger::toQByteArray(bool big_endian) const
{
    int byte_len = this->bytesLength();
    QByteArray arr(this->bytesData(), byte_len);
    if(big_endian){
        int half_len = byte_len / 2;
        int ilast = byte_len - 1;
        for(int i = 0; i < half_len; ++i, --ilast){
            char t = arr[i];
            arr[i] = arr[ilast];
            arr[ilast] = t;
        }
    }
    return arr;
}

ECInteger ECInteger::clone() const
{
    uint *digits = new uint[this->_pimpl->_digit_length];
    for(int i = 0; i < this->_pimpl->_digit_length; ++i)
        digits[i] = this->_pimpl->_digits[i];
    return ECInteger(digits, this->_pimpl->_digit_length, this->_pimpl->_sign, true);
}

ECInteger ECInteger::parse(const char *chars)
{
    char *value = (char *)chars;
    int sign = 1;
    if(chars[0] == '-'){
        sign = -1;
        value = (char *)&chars[1];
    }
    int count = 0;
    char c = value[0];
    while(c != 0){
        if(c < 48 || 57 < c)
            throw std::runtime_error("Used invalid numeric literal for parsing string.");
        ++count;
        c = value[count];
    }

    int zeroTrim = 0;
    c = value[0];
    while(c == 48){
        ++zeroTrim;
        c = value[zeroTrim];
    }
    char *start = &value[zeroTrim];
    count -= zeroTrim;
    int digitLength;
    uint *digits = ECIntegerBasicOperators::unsignedParse(start, count, digitLength);
    if(digitLength == 1 && digits[0] == 0)
        sign = 0;
    return ECInteger(digits, digitLength, sign, true);
}
ECInteger ECInteger::parse(const QString &value)
{
    return ECInteger::parse(value.toUtf8().data());
}

ECInteger ECInteger::parseFromHex(const QString &hexstr)
{
    std::string hex = hexstr.toUtf8().data();
    bool isNeg = hex[0] == ('-');
    if (isNeg)
        hex = hex.substr(1, hex.size() - 1);

    std::transform(hex.begin(), hex.end(), hex.begin(), ::tolower);

    if (hex.rfind("0x") == 0)
        hex = hex.substr(2, hex.size() - 2);

    int byteLength = (hex.size() + 1) / 2;
    unsigned char *bytes = new unsigned char[byteLength];
    for(int i = 0; i < byteLength; ++i)
        bytes[i] = 0;

    std::string zero = "0";
    if ((hex.size() & 1) == 1)
        hex = zero.append(hex);
    for (int i = 0; i < byteLength; ++i)
    {
        char c1 = hex[2 * i];
        char c2 = hex[2 * i + 1];
        if (c1 > 96)
            bytes[i] |= (unsigned char)((c1 - 87) << 4);
        else
            bytes[i] |= (unsigned char)((c1 - 48) << 4);

        if (c2 > 96)
            bytes[i] |= (unsigned char)((c2 - 87));
        else
            bytes[i] |= (unsigned char)((c2 - 48));
    }
    int digitLength;
    uint *digits = ECIntegerBasicOperators::fromUnsignedBytes(bytes, byteLength, true, digitLength);
    delete[] bytes;
    if (digitLength == 1 && digits[0] == 0)
        return 0;
    return ECInteger(digits, digitLength, isNeg ? -1 : 1, true);
}

ECInteger ECInteger::random(const long &bytes_length)
{
    QByteArray bytes = DRBG::fromRandomSeed().generate(bytes_length);
    return ECInteger(bytes.data(), bytes_length, 1);
}

void ECInteger::swap(ECInteger &l, ECInteger &r)
{
    ECInteger t = r;
    r = l.clone();
    l = t.clone();
}

QVector<int> ECInteger::nonAdjacentForm(const int &window) const
{
    ECInteger d = this->clone();
    int modulus = 1 << window;

    QVector<int> naf (d.bitsLength() + 1, '\0');

    int modMinOne = modulus - 1;
    int halfOfModulus = modulus >> 1;
    for (int i = 0; !d.isZero(); ++i)
    {
        if (d.isOdd())
        {
            int mod = (int)d.firstDigit() & modMinOne; //d mod 2 ^ w

            if (mod >= halfOfModulus)
            {
                int inc = modulus - mod;
                naf[i] = -inc;
                d += inc;
            }
            else
            {
                naf[i] = mod;
                d -= (uint)mod;
            }
        }
        d = d >> 1;
    }
    return naf;
}

int ECInteger::compare(const ECInteger &left, const ECInteger &right)
{
    if(left._pimpl->_sign > right._pimpl->_sign)
        return 1;
    if(left._pimpl->_sign < right._pimpl->_sign)
        return -1;
    return ECIntegerBasicOperators::compare(left._pimpl->_digits, left._pimpl->_digit_length, right._pimpl->_digits, right._pimpl->_digit_length);
}

ECInteger ECInteger::modInverse(const ECInteger &value, const ECInteger &modulus)
{
    if (value.isOne())
        return ECInteger(1u);

    ECInteger x1 = ECInteger::zero(), x2 = modulus.clone(), y1 = ECInteger::one(), y2 = value.clone();

    ECInteger t1, t2, q = ECInteger::divrem(x2, y2, t2);
    q.negate();
    t1 = q.clone();

    while (!y2.isOne())
    {
        if (t2.isZero())
            return ECInteger::zero();

        x1 = y1.clone(); x2 = y2.clone();
        y1 = t1.clone(); y2 = t2.clone();
        q = ECInteger::divrem(x2, y2, t2);

        t1 = x1 - q * y1;
    }
    if (y1.sign() == -1)
        return y1 + modulus;
    else
        return y1;
}

ECInteger ECInteger::square(const ECInteger &value)
{
    return value.clone().square();
}

ECInteger::operator int() const
{
    uint f_digit = this->_pimpl->_digits[0];
    f_digit -= (f_digit > 0x7FFFFFFF) * 0x7FFFFFFF;
    return (int)f_digit * this->_pimpl->_sign;
}
ECInteger::operator uint() const
{
    uint f_digit = this->_pimpl->_digits[0];
    return (uint)(f_digit * this->_pimpl->_sign);
}
ECInteger::operator long() const
{
    if(this->_pimpl->_digit_length > 1){
        ulong dig = ((ulong *)this->_pimpl->_digits)[0];
        dig -= (dig > 0x7FFFFFFFFFFFFFFF) * 0x7FFFFFFFFFFFFFFF;
        return (long)dig * this->_pimpl->_sign;
    } else {
        long f_digit = this->_pimpl->_digits[0];
        return f_digit * this->_pimpl->_sign;
    }
}
ECInteger::operator ulong() const
{
    if(this->_pimpl->_digit_length > 1){
        ulong dig = ((ulong *)this->_pimpl->_digits)[0];
        return (ulong)dig * this->_pimpl->_sign;
    } else {
        ulong f_digit = this->_pimpl->_digits[0];
        return f_digit * this->_pimpl->_sign;
    }
}

ECInteger::ECInteger(uint *digits, int length, int sign, bool internal)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);

    if(internal){
        if(length == 0){
            delete[] digits;
            this->_pimpl->_digit_length = 1;
            this->_pimpl->_digits = new uint[1] { 0 };
            this->_pimpl->_sign = 0;
        } else {
            if(length == 1 && digits[0] == 0)
                this->_pimpl->_sign = 0;
            else
                this->_pimpl->_sign = sign;
            if(sign == 0){
                this->_pimpl->_digit_length = 1;
                this->_pimpl->_digits = new uint[1] { 0 };
                this->_pimpl->_sign = 0;
            } else{
                this->_pimpl->_digits = digits;
                this->_pimpl->_digit_length = length;
            }
        }
    } else {
        if(length == 0){
            this->_pimpl->_sign = 0;
            this->_pimpl->_digit_length = length;
            this->_pimpl->_digits = new uint[1] { 0 };
        } else {
            while(digits[length - 1] == 0 && length > 1)
                --length;
            if(length == 1 && digits[0] == 0)
                this->_pimpl->_sign = 0;
            else
                this->_pimpl->_sign = sign;
            if(sign == 0){
                this->_pimpl->_digit_length = 1;
                this->_pimpl->_digits = new uint[1] { 0 };
                this->_pimpl->_sign = 0;
            } else {
                this->_pimpl->_digit_length = length;
                this->_pimpl->_digits = new uint[length];
                for(int i = 0; i < length; ++i)
                    this->_pimpl->_digits[i] = digits[i];
            }
        }
    }
}

////////////////////////////////////////////////// Elliptic Curve Algorithms //////////////////////////////////////////////////////////////////////

bool ECPoint::isZero() const { return this->X.isZero() && this->Y.isZero(); }

ECPoint::ECPoint(const ECInteger &x, const ECInteger &y, const ECInteger &z)
{
    this->X = x;
    this->Y = y;
    this->Z = z;
}

QString ECPoint::toQString() const
{
    QString str = "(";
    return str.append(this->X.toQString()).append(", ").append(this->Y.toQString()).append(")");
}

ECPoint ECPoint::clone() const
{
    return ECPoint(this->X.clone(), this->Y.clone(), this->Z.clone());
}

ECArithmeticsGFp::ECArithmeticsGFp(const QString &urn, bool deterministic)
{
    this->Deterministic = deterministic;
    if(urn.compare("urn:oid:1.3.132.0.6") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("659EF8BA043916EEDE8911702B22");
        this->P = ECInteger::parseFromHex("DB7C2ABF62E35E668076BEAD208B");
        this->N = ECInteger::parseFromHex("DB7C2ABF62E35E7628DFAC6561C5");
        this->G = ECPoint(ECInteger::parseFromHex("09487239995A5EE76B55F9C2F098"),
                          ECInteger::parseFromHex("A89CE5AF8724C0A23E0E0FF77500"));
        this->H = 1u;
        this->BitLength = 112;
        this->URN = "urn:oid:1.3.132.0.6";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.7") == 0){
        this->A = ECInteger::parseFromHex("6127C24C05F38A0AAAF65C0EF02C");
        this->B = ECInteger::parseFromHex("51DEF1815DB5ED74FCC34C85D709");
        this->P = ECInteger::parseFromHex("DB7C2ABF62E35E668076BEAD208B");
        this->N = ECInteger::parseFromHex("36DF0AAFD8B8D7597CA10520D04B");
        this->G = ECPoint(ECInteger::parseFromHex("4BA30AB5E892B4E1649DD0928643"),
                          ECInteger::parseFromHex("ADCD46F5882E3747DEF36E956E97"));
        this->H = 4u;
        this->BitLength = 112;
        this->URN = "urn:oid:1.3.132.0.7";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.28") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("E87579C11079F43DD824993C2CEE5ED3");
        this->P = ECInteger::parseFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFE0000000075A30D1B9038A115");
        this->G = ECPoint(ECInteger::parseFromHex("161FF7528B899B2D0C28607CA52C5B86"),
                          ECInteger::parseFromHex("CF5AC8395BAFEB13C02DA292DDED7A83"));
        this->H = 1u;
        this->BitLength = 128;
        this->URN = "urn:oid:1.3.132.0.28";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.29") == 0){
        this->A = ECInteger::parseFromHex("D6031998D1B3BBFEBF59CC9BBFF9AEE1");
        this->B = ECInteger::parseFromHex("5EEEFCA380D02919DC2C6558BB6D8A5D");
        this->P = ECInteger::parseFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("3FFFFFFF7FFFFFFFBE0024720613B5A3");
        this->G = ECPoint(ECInteger::parseFromHex("7B6AA5D85E572983E6FB32A7CDEBC140"),
                          ECInteger::parseFromHex("27B6916A894D3AEE7106FE805FC34B44"));
        this->H = 4u;
        this->BitLength = 128;
        this->URN = "urn:oid:1.3.132.0.29";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.9") == 0){
        this->A = 0u;
        this->B = 7u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
        this->N = ECInteger::parseFromHex("100000000000000000001B8FA16DFAB9ACA16B6B3");
        this->G = ECPoint(ECInteger::parseFromHex("3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"),
                          ECInteger::parseFromHex("938CF935318FDCED6BC28286531733C3F03C4FEE"));
        this->H = 1u;
        this->BitLength = 160;
        this->URN = "urn:oid:1.3.132.0.9";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.8") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
        this->N = ECInteger::parseFromHex("100000000000000000001F4C8F927AED3CA752257");
        this->G = ECPoint(ECInteger::parseFromHex("4A96B5688EF573284664698968C38BB913CBFC82"),
                          ECInteger::parseFromHex("23A628553168947D59DCC912042351377AC5FB32"));
        this->H = 1u;
        this->BitLength = 160;
        this->URN = "urn:oid:1.3.132.0.8";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.30") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("B4E134D3FB59EB8BAB57274904664D5AF50388BA");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
        this->N = ECInteger::parseFromHex("100000000000000000000351EE786A818F3A1A16B");
        this->G = ECPoint(ECInteger::parseFromHex("52DCB034293A117E1F4FF11B30F7199D3144CE6D"),
                          ECInteger::parseFromHex("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E"));
        this->H = 1u;
        this->BitLength = 160;
        this->URN = "urn:oid:1.3.132.0.30";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.31") == 0){
        this->A = 0u;
        this->B = 3u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
        this->G = ECPoint(ECInteger::parseFromHex("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"),
                          ECInteger::parseFromHex("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"));
        this->H = 1u;
        this->BitLength = 192;
        this->URN = "urn:oid:1.3.132.0.31";
        return;
    }
    if(urn.compare("urn:oid:1.2.840.10045.3.1.1") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
        this->G = ECPoint(ECInteger::parseFromHex("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"),
                          ECInteger::parseFromHex("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"));
        this->H = 1u;
        this->BitLength = 192;
        this->URN = "urn:oid:1.2.840.10045.3.1.1";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.32") == 0){
        this->A = 0u;
        this->B = 5u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D");
        this->N = ECInteger::parseFromHex("10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7");
        this->G = ECPoint(ECInteger::parseFromHex("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"),
                          ECInteger::parseFromHex("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"));
        this->H = 1u;
        this->BitLength = 224;
        this->URN = "urn:oid:1.3.132.0.32";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.33") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
        this->G = ECPoint(ECInteger::parseFromHex("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"),
                          ECInteger::parseFromHex("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"));
        this->H = 1u;
        this->BitLength = 224;
        this->URN = "urn:oid:1.3.132.0.33";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.10") == 0){
        this->A = 0u;
        this->B = 7u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        this->G = ECPoint(ECInteger::parseFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                          ECInteger::parseFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
        this->H = 1u;
        this->BitLength = 256;
        this->URN = "urn:oid:1.3.132.0.10";
        return;
    }
    if(urn.compare("urn:oid:1.2.840.10045.3.1.7") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
        this->P = ECInteger::parseFromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        this->G = ECPoint(ECInteger::parseFromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                          ECInteger::parseFromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
        this->H = 1u;
        this->BitLength = 256;
        this->URN = "urn:oid:1.2.840.10045.3.1.7";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.34") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
        this->G = ECPoint(ECInteger::parseFromHex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
                          ECInteger::parseFromHex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));
        this->H = 1u;
        this->BitLength = 384;
        this->URN = "urn:oid:1.3.132.0.34";
        return;
    }
    if(urn.compare("urn:oid:1.3.132.0.35") == 0){
        this->A = -3;
        this->B = ECInteger::parseFromHex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");
        this->P = ECInteger::parseFromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");
        this->G = ECPoint(ECInteger::parseFromHex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
                          ECInteger::parseFromHex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));
        this->H = 1u;
        this->BitLength = 521;
        this->URN = "urn:oid:1.3.132.0.35";
        return;
    }
    this->A = -3;
    this->B = ECInteger::parseFromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    this->P = ECInteger::parseFromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    this->N = ECInteger::parseFromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    this->G = ECPoint(ECInteger::parseFromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                      ECInteger::parseFromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
    this->H = 1u;
    this->BitLength = 256;
    this->URN = "urn:oid:1.2.840.10045.3.1.7";
}

ECArithmeticsGFp::ECArithmeticsGFp(ECC::CurveName name, bool deterministic)
{
    this->Deterministic = deterministic;
    switch (name) {
    case ECC::CURVE_SECP112R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("659EF8BA043916EEDE8911702B22");
        this->P = ECInteger::parseFromHex("DB7C2ABF62E35E668076BEAD208B");
        this->N = ECInteger::parseFromHex("DB7C2ABF62E35E7628DFAC6561C5");
        this->G = ECPoint(ECInteger::parseFromHex("09487239995A5EE76B55F9C2F098"),
                          ECInteger::parseFromHex("A89CE5AF8724C0A23E0E0FF77500"));
        this->H = 1u;
        this->BitLength = 112;
        this->URN = "urn:oid:1.3.132.0.6";
        break;
    case ECC::CURVE_SECP112R2:
        this->A = ECInteger::parseFromHex("6127C24C05F38A0AAAF65C0EF02C");
        this->B = ECInteger::parseFromHex("51DEF1815DB5ED74FCC34C85D709");
        this->P = ECInteger::parseFromHex("DB7C2ABF62E35E668076BEAD208B");
        this->N = ECInteger::parseFromHex("36DF0AAFD8B8D7597CA10520D04B");
        this->G = ECPoint(ECInteger::parseFromHex("4BA30AB5E892B4E1649DD0928643"),
                          ECInteger::parseFromHex("ADCD46F5882E3747DEF36E956E97"));
        this->H = 4u;
        this->BitLength = 112;
        this->URN = "urn:oid:1.3.132.0.7";
        break;
    case ECC::CURVE_SECP128R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("E87579C11079F43DD824993C2CEE5ED3");
        this->P = ECInteger::parseFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFE0000000075A30D1B9038A115");
        this->G = ECPoint(ECInteger::parseFromHex("161FF7528B899B2D0C28607CA52C5B86"),
                          ECInteger::parseFromHex("CF5AC8395BAFEB13C02DA292DDED7A83"));
        this->H = 1u;
        this->BitLength = 128;
        this->URN = "urn:oid:1.3.132.0.28";
        break;
    case ECC::CURVE_SECP128R2:
        this->A = ECInteger::parseFromHex("D6031998D1B3BBFEBF59CC9BBFF9AEE1");
        this->B = ECInteger::parseFromHex("5EEEFCA380D02919DC2C6558BB6D8A5D");
        this->P = ECInteger::parseFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("3FFFFFFF7FFFFFFFBE0024720613B5A3");
        this->G = ECPoint(ECInteger::parseFromHex("7B6AA5D85E572983E6FB32A7CDEBC140"),
                          ECInteger::parseFromHex("27B6916A894D3AEE7106FE805FC34B44"));
        this->H = 4u;
        this->BitLength = 128;
        this->URN = "urn:oid:1.3.132.0.29";
        break;
    case ECC::CURVE_SECP160K1:
        this->A = 0u;
        this->B = 7u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
        this->N = ECInteger::parseFromHex("100000000000000000001B8FA16DFAB9ACA16B6B3");
        this->G = ECPoint(ECInteger::parseFromHex("3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"),
                          ECInteger::parseFromHex("938CF935318FDCED6BC28286531733C3F03C4FEE"));
        this->H = 1u;
        this->BitLength = 160;
        this->URN = "urn:oid:1.3.132.0.9";
        break;
    case ECC::CURVE_SECP160R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
        this->N = ECInteger::parseFromHex("100000000000000000001F4C8F927AED3CA752257");
        this->G = ECPoint(ECInteger::parseFromHex("4A96B5688EF573284664698968C38BB913CBFC82"),
                          ECInteger::parseFromHex("23A628553168947D59DCC912042351377AC5FB32"));
        this->H = 1u;
        this->BitLength = 160;
        this->URN = "urn:oid:1.3.132.0.8";
        break;
    case ECC::CURVE_SECP160R2:
        this->A = -3;
        this->B = ECInteger::parseFromHex("B4E134D3FB59EB8BAB57274904664D5AF50388BA");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
        this->N = ECInteger::parseFromHex("100000000000000000000351EE786A818F3A1A16B");
        this->G = ECPoint(ECInteger::parseFromHex("52DCB034293A117E1F4FF11B30F7199D3144CE6D"),
                          ECInteger::parseFromHex("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E"));
        this->H = 1u;
        this->BitLength = 160;
        this->URN = "urn:oid:1.3.132.0.30";
        break;
    case ECC::CURVE_SECP192K1:
        this->A = 0u;
        this->B = 3u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
        this->G = ECPoint(ECInteger::parseFromHex("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"),
                          ECInteger::parseFromHex("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"));
        this->H = 1u;
        this->BitLength = 192;
        this->URN = "urn:oid:1.3.132.0.31";
        break;
    case ECC::CURVE_SECP192R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
        this->G = ECPoint(ECInteger::parseFromHex("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"),
                          ECInteger::parseFromHex("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"));
        this->H = 1u;
        this->BitLength = 192;
        this->URN = "urn:oid:1.2.840.10045.3.1.1";
        break;
    case ECC::CURVE_SECP224K1:
        this->A = 0u;
        this->B = 5u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D");
        this->N = ECInteger::parseFromHex("10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7");
        this->G = ECPoint(ECInteger::parseFromHex("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"),
                          ECInteger::parseFromHex("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"));
        this->H = 1u;
        this->BitLength = 224;
        this->URN = "urn:oid:1.3.132.0.32";
        break;
    case ECC::CURVE_SECP224R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
        this->G = ECPoint(ECInteger::parseFromHex("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"),
                          ECInteger::parseFromHex("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"));
        this->H = 1u;
        this->BitLength = 224;
        this->URN = "urn:oid:1.3.132.0.33";
        break;
    case ECC::CURVE_SECP256K1:
        this->A = 0u;
        this->B = 7u;
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        this->G = ECPoint(ECInteger::parseFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                          ECInteger::parseFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
        this->H = 1u;
        this->BitLength = 256;
        this->URN = "urn:oid:1.3.132.0.10";
        break;
    case ECC::CURVE_SECP256R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
        this->P = ECInteger::parseFromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        this->G = ECPoint(ECInteger::parseFromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                          ECInteger::parseFromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
        this->H = 1u;
        this->BitLength = 256;
        this->URN = "urn:oid:1.2.840.10045.3.1.7";
        break;
    case ECC::CURVE_SECP384R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");
        this->P = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
        this->G = ECPoint(ECInteger::parseFromHex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
                          ECInteger::parseFromHex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));
        this->H = 1u;
        this->BitLength = 384;
        this->URN = "urn:oid:1.3.132.0.34";
        break;
    case ECC::CURVE_SECP521R1:
        this->A = -3;
        this->B = ECInteger::parseFromHex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");
        this->P = ECInteger::parseFromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");
        this->G = ECPoint(ECInteger::parseFromHex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
                          ECInteger::parseFromHex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));
        this->H = 1u;
        this->BitLength = 521;
        this->URN = "urn:oid:1.3.132.0.35";
        break;
    default: //CURVE_SECP256R1
        this->A = -3;
        this->B = ECInteger::parseFromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
        this->P = ECInteger::parseFromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        this->N = ECInteger::parseFromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        this->G = ECPoint(ECInteger::parseFromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                          ECInteger::parseFromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
        this->H = 1u;
        this->BitLength = 256;
        this->URN = "urn:oid:1.2.840.10045.3.1.7";
        break;
    }
}

bool ECArithmeticsGFp::checkValidPoint(const ECPoint &point) const
{
    ECPoint clone = point.clone();
    if (!clone.Z.isOne())
        clone = this->jacobianToAffine(clone);
    return clone.Y.square() % this->P == (clone.X.cube() + this->A * point.X + this->B) % this->P;
}

ECPoint ECArithmeticsGFp::affineDoubling(const ECPoint &P) const
{
    if (P.Y.isZero())
        return ECPoint();

    ECInteger px2 = ECInteger::square(P.X);
    ECInteger px2c = px2.clone();
    px2.leftShift(1);
    px2 += px2c + this->A;

    ECInteger m = ((px2) * ECInteger::modInverse((P.Y << 1), this->P)) % this->P;
    ECInteger X = (ECInteger::square(m) - (P.X << 1)) % this->P;
    ECInteger Y = (m * (P.X - X) - P.Y) % this->P;
    if (X.isNegative())
        X += this->P;
    if (Y.isNegative())
        Y += this->P;
    return ECPoint(X, Y);
}

ECPoint ECArithmeticsGFp::affineAddition(const ECPoint &P, const ECPoint &Q) const
{
    if (P.isZero())
        return Q.clone();
    if (Q.isZero())
        return P.clone();

    ECInteger den = Q.X - P.X;
    ECInteger num = Q.Y - P.Y;
    if (den.isZero())
    {
        if (num.isZero())
            this->affineDoubling(P);
        return ECPoint();
    }
    if (den.sign() == -1)
        den += this->P;

    ECInteger m = (num * ECInteger::modInverse(den, this->P)) % this->P;
    ECInteger X = (m.clone().square() - (P.X + Q.X)) % this->P;
    ECInteger Y = (m * (P.X - X) - P.Y) % this->P;

    if (X.isNegative())
        X += this->P;
    if (Y.isNegative())
        Y += this->P;
    return ECPoint(X, Y);
}

ECPoint ECArithmeticsGFp::jacobianDoubling(const ECPoint &P) const //4M + 6S //A = -3 => 4M + 5S //A = 0 => 4M + 4S
{
    if (P.Y.isZero())
        return ECPoint();

    ECInteger X = P.X, Y = P.Y, Z = P.Z;
    ECInteger N;

    if (this->A.isZero())
    {
        N = this->modulo(X * X * 3);
    }
    else if (this->A == -3)
    {
        ECInteger Z2 = this->modulo(Z * Z);
        N = this->modulo((X + Z2) * (X - Z2) * 3);
    }
    else
    {
        ECInteger Z4 = this->modulo(this->modulo(Z * Z).square());
        N = this->modulo(X * X * 3 + this->A * Z4);
    }

    ECInteger Y2 = this->modulo(Y * Y), T = this->modulo(X * (Y2 << 2));

    ECInteger Xr = this->modulo(N * N - (T << 1));
    ECInteger Yr = this->modulo(N * (T - Xr) - ((Y2 << 3) * Y2));
    ECInteger Zr = this->modulo(Y * (Z << 1));

    if (Xr.isNegative())
        Xr += this->P;
    if (Yr.isNegative())
        Yr += this->P;
    if (Zr.isNegative())
        Zr += this->P;

    return ECPoint(Xr, Yr, Zr);
}

ECPoint ECArithmeticsGFp::jacobianAddition(const ECPoint &P, const ECPoint &Q) const //13M + 4S
{
    if (P.isZero())
        return Q.clone();
    if (Q.isZero())
        return P.clone();

    ECInteger Xp = P.X, Yp = P.Y, Zp = P.Z, Zp2 = this->modulo(Zp * Zp), Zp3 = this->modulo(Zp2 * Zp);// % this->P;
    ECInteger Xq = Q.X, Yq = Q.Y, Zq = Q.Z, Zq2 = this->modulo(Zq * Zq), Zq3 = this->modulo(Zq2 * Zq);// % this->P;
    ECInteger Xt = this->modulo(Xq * Zp2), Xg = this->modulo(Xp * Zq2), YPZQ3 = this->modulo(Yp * Zq3);// % this->P;

    ECInteger D = Xg - Xt, N = (YPZQ3 - Yq * Zp3) % this->P;

    if (D.isZero())
    {
        if (N.isZero())
            return this->doubling(P);
        return ECPoint();
    }

    ECInteger D2 = this->modulo(D * D);

    ECInteger Xr = this->modulo(N * N - (Xg + Xt) * D2);
    ECInteger Yr = this->modulo(N * (this->modulo(Xg * D2 - Xr)) - (this->modulo(YPZQ3 * D2) * D));
    ECInteger Zr = this->modulo(this->modulo(Zp * Zq) * D);

    if (Xr.isNegative())
        Xr += this->P;
    if (Yr.isNegative())
        Yr += this->P;
    if (Zr.isNegative())
        Zr += this->P;

    return ECPoint(Xr, Yr, Zr);
}

ECPoint ECArithmeticsGFp::modifiedJacobianDoubling(const ECPoint &P, ECInteger &aZ4) const
{
    if (P.Y.isZero())
    {
        aZ4 = 1;
        return ECPoint();
    }

    ECInteger X = P.X, Y = P.Y, Z = P.Z;
    ECInteger N = this->modulo((X * X * 3) + aZ4);

    ECInteger Y2 = this->modulo(Y * Y), Y4 = this->modulo(Y2 * Y2), T = this->modulo(X * (Y2 << 2));

    ECInteger Xr = this->modulo(N * N - (T << 1));
    ECInteger Yr = this->modulo((N * (T - Xr) - (Y4 << 3)));
    ECInteger Zr = this->modulo(Y * (Z << 1));

    if (!aZ4.isZero())
        aZ4 = this->modulo(Y4 * aZ4 * 16);

    if (Xr.isNegative())
        Xr += this->P;
    if (Yr.isNegative())
        Yr += this->P;
    if (Zr.isNegative())
        Zr += this->P;

    return ECPoint(Xr, Yr, Zr);
}

ECPoint ECArithmeticsGFp::doubleAndAdd(const ECPoint &P, const ECPoint &Q) const //17M + 10S
{
    ECPoint D = this->doubling(P);
    return this->addition(D, Q);
}

ECPoint ECArithmeticsGFp::binaryMultiplication(const ECPoint &point, const ECInteger &d) const
{
    ECInteger dm = d % this->N;

    if (dm.isZero())
        return ECPoint();
    else if (dm.isOne())
        return point.clone();

    ECPoint res;
    int bit = dm.bit(0);
    if (bit == 1)
        res = point.clone();

    int bitLength = (int)dm.bitsLength();
    ECPoint d_point = point.clone();
    for (int i = 1; i < bitLength; ++i)
    {
        d_point = this->doubling(d_point);
        bit = dm.bit(i);
        if (bit == 1)
            res = this->addition(d_point, res);
    }
    return res;
}

ECPoint ECArithmeticsGFp::wNAFMultiplication(const ECPoint &point, const ECInteger &d, const int &w) const
{
    ECInteger dm = d % this->N;
    if (dm.isZero())
        return ECPoint();
    else if (dm.isOne())
        return point.clone();
    else if (dm.firstDigit() == 2 && dm.digitLength() == 1)
        return this->doubling(point);

    QVector<int> naf = dm.nonAdjacentForm(w);
    QVector<ECPoint> preCompPoints = this->pointPrecomputationsForNAF(point, w);

    ECPoint Q = ECPoint();
    for (int i = naf.size() - 1; i >= 0; --i)
    {
        Q = this->doubling(Q);
        int nafBit = naf[i];
        if (nafBit > 0)
            Q = this->addition(preCompPoints[nafBit], Q);
        else if (nafBit < 0)
            Q = this->addition(preCompPoints[-nafBit - 1], Q);
    }
    return Q;
}

ECPoint ECArithmeticsGFp::fixedBaseMultiplication(const ECPoint &P, const ECInteger &k, const int &w) const
{
    QVector<ECPoint> preComputes = this->fixedPointCombPreComputes(P, w);
    return this->fixedBaseMultiplication(preComputes, k, w);
}

ECPoint ECArithmeticsGFp::fixedBaseMultiplication(const QVector<ECPoint> &preComputes, const ECInteger &k, const int &w) const
{
    int bitLen = this->BitLength;
    int d = (bitLen + w - 1) / w;

    ECPoint mul = ECPoint();

    int t = d * w - 1;
    for (int i = 0; i < d; ++i)
    {
        int preCompIndex = 0;
        for (int j = t - i; j > -1; j -= d)
        {
            preCompIndex <<= 1;
            preCompIndex |= k.bit(j);
        }
        mul = this->doubleAndAdd(mul, preComputes[preCompIndex]);
    }
    return mul;
}

ECPoint ECArithmeticsGFp::shamirsTrick(const ECInteger &u1, const ECPoint &G, const ECInteger &u2, const ECPoint &D) const
{
    ECInteger u1m = u1 % this->N;
    ECInteger u2m = u2 % this->N;

    int u1BitLen = (int)u1m.bitsLength();
    int u2BitLen = (int)u2m.bitsLength();
    int bitLen = u1BitLen < u2BitLen ? u2BitLen : u1BitLen;

    ECPoint GD = this->addition(G, D);

    ECPoint res = ECPoint();

    for (int i = bitLen - 1; i > 0; --i)
    {
        int bits = u1m.bit(i) << 1;
        bits |= u2m.bit(i);

        if (bits == 2)
            res = this->addition(G, res);
        else if (bits == 1)
            res = this->addition(D, res);
        else if (bits == 3)
            res = this->addition(GD, res);
        res = this->doubling(res);
    }
    {
        int bits = u1m.bit(0) << 1;
        bits |= u2m.bit(0);

        if (bits == 2)
            res = this->addition(G, res);
        else if (bits == 1)
            res = this->addition(D, res);
        else if (bits == 3)
            res = this->addition(GD, res);
    }
    return res;
}

ECPoint ECArithmeticsGFp::interleavingWithNAF(const ECInteger &u1, const ECPoint &G, const ECInteger &u2, const ECPoint &D) const
{
    ECInteger u1m = u1 % this->N;
    ECInteger u2m = u2 % this->N;

    ECPoint Dc = D.clone();
    ECPoint Gc = G.clone();

    if (u1m.bitsLength() < u2m.bitsLength())
    {
        ECInteger::swap(u1m, u2m);
        ECPoint tempEC = D;
        Dc = G;
        Gc = tempEC;
    }

    ECPoint nG = this->negate(Gc);
    ECPoint nD = this->negate(Dc);
    ECPoint GD = this->addition(Gc, Dc);
    ECPoint nGD = this->negate(GD);
    ECPoint GminD = this->addition(Gc, nD);
    ECPoint DminG = this->negate(GminD);

    QVector<int> u1Naf = u1m.nonAdjacentForm(2);
    QVector<int> u2Naf = u2m.nonAdjacentForm(2);

    ECPoint res = ECPoint();

    for (int i = u1Naf.size() - 1; i > -1; --i)
    {
        res = this->doubling(res);

        int minBit = 0, maxBit = u1Naf[i];
        if (i < (int)u2Naf.size())
            minBit = u2Naf[i];
        if (minBit == -1)
        {
            if (maxBit == -1)
                res = this->addition(nGD, res);
            else if (maxBit == 1)
                res = this->addition(GminD, res);
            else
                res = this->addition(nD, res);
        }
        else if (minBit == 0)
        {
            if (maxBit == -1)
                res = this->addition(nG, res);
            else if (maxBit == 1)
                res = this->addition(Gc, res);
        }
        else if (minBit == 1)
        {
            if (maxBit == -1)
                res = this->addition(DminG, res);
            else if (maxBit == 1)
                res = this->addition(GD, res);
            else
                res = this->addition(Dc, res);
        }
    }
    return res;
}

ECPoint ECArithmeticsGFp::interleavingWithwNAF(const ECInteger &u1, const ECPoint &G, const int &w1, const ECInteger &u2, const ECPoint &D, const int &w2) const
{
    ECInteger u1m = u1 % this->N;
    ECInteger u2m = u2 % this->N;

    ECPoint Dc = D.clone();
    ECPoint Gc = G.clone();

    if (u1m.bitsLength() < u2m.bitsLength())
    {
        ECInteger::swap(u1m, u2m);
        ECPoint tempEC = Dc;
        Dc = Gc;
        Gc = tempEC;
    }

    QVector<int> u1Naf = u1m.nonAdjacentForm(w1);
    QVector<int> u2Naf = u2m.nonAdjacentForm(w2);

    QVector<ECPoint> u1PreComputes = this->pointPrecomputationsForNAF(Gc, w1);
    QVector<ECPoint> u2PreComputes = this->pointPrecomputationsForNAF(Dc, w2);

    return this->interleavingWithwNAF(u1Naf, u1PreComputes, u2Naf, u2PreComputes);
}

ECPoint ECArithmeticsGFp::interleavingWithwNAF(const QVector<int> &u1Naf, const QVector<ECPoint> &precomputesOfG, const QVector<int> &u2Naf, const QVector<ECPoint> &precomputesOfD) const
{
    ECPoint res = ECPoint();

    for (int i = (int)u1Naf.size() - 1; i >= (int)u2Naf.size(); --i)
    {
        int maxBit = u1Naf[i];
        if (maxBit == 0)
            res = this->doubling(res);
        else
            if (maxBit > 0)
                res = this->doubleAndAdd(res, precomputesOfG[maxBit]);
            else
                res = this->doubleAndAdd(res, precomputesOfG[-maxBit - 1]);
    }
    for (int i = u2Naf.size() - 1; i > -1; --i)
    {
        bool added = false;
        ECPoint adder = ECPoint();
        int minBit = u2Naf[i], maxBit = u1Naf[i];
        if (minBit != 0)
        {
            if (minBit > 0)
                adder = precomputesOfD[minBit];
            else
                adder = precomputesOfD[-minBit - 1];
            added = true;
        }
        if (maxBit != 0)
        {
            if (maxBit > 0)
                adder = this->addition(adder, precomputesOfG[maxBit]);
            else
                adder = this->addition(adder, precomputesOfG[-maxBit - 1]);
            added = true;
        }
        if (added)
            res = this->doubleAndAdd(res, adder);
        else
            res = this->doubling(res);
    }
    return res;
}

ECInteger ECArithmeticsGFp::calculateAZ4(const ECPoint &P) const
{
    return this->A * (P.Z * P.Z % this->P).square() % this->P;
}

QVector<ECPoint> ECArithmeticsGFp::pointPrecomputationsForNAF(const ECPoint &point, const int &w) const
{
    int preCompCount = 1 << (w - 2);
    QVector<ECPoint> preCompPoints;
    preCompPoints.resize(preCompCount * 2);
    preCompPoints[1] = point;
    preCompPoints[0] = this->negate(point);
    for (int i = 1; i < preCompCount; ++i)
    {
        int bit = 2 * i + 1;
        ECPoint P = this->binaryMultiplication(point, (ECInteger)bit);
        preCompPoints[bit] = P;
        preCompPoints[bit - 1] = this->negate(P);
    }
    return preCompPoints;
}

QVector<ECPoint> ECArithmeticsGFp::fixedPointCombPreComputes(const ECPoint &point, const int &w) const
{
    int n = 1 << w;

    int bitLen = this->BitLength;
    int d = (bitLen + w - 1) / w;
    QVector<ECPoint> twoPowNList;
    twoPowNList.resize(w);
    twoPowNList[0] = point;
    for (int i = 1; i < w; ++i)
    {
        ECPoint Q = twoPowNList[i - 1];
        for (int j = 0; j < d; ++j)
            Q = this->doubling(Q);
        twoPowNList[i] = Q;
    }

    QVector<ECPoint> preComputes;
    preComputes.resize(n);
    preComputes[0] = ECPoint();

    for (int bit = w - 1; bit > -1; --bit)
    {
        ECPoint pow2 = twoPowNList[bit];

        int adderIndex = 1 << bit;
        int i = adderIndex;
        while (i < n)
        {
            preComputes[i] = this->addition(preComputes[i - adderIndex], pow2);
            i += (adderIndex << 1);
        }
    }
    return preComputes;
}

ECInteger ECArithmeticsGFp::modulo(const ECInteger &value) const
{
    return value % this->P;
}

ECPoint ECArithmeticsGFp::negate(const ECPoint &R) const
{
    ECInteger Y = this->P - R.Y;
    return ECPoint(R.X, Y, R.Z);
}

ECPoint ECArithmeticsGFp::jacobianToAffine(const ECPoint &point) const
{
    ECInteger invZ = ECInteger::modInverse(point.Z, this->P), invZ2 = (invZ * invZ) % this->P, invZ3 = (invZ2 * invZ) % this->P;
    ECInteger X = point.X * invZ2 % this->P;
    ECInteger Y = point.Y * invZ3 % this->P;
    return ECPoint(X, Y, 1);
}

ECInteger ECArithmeticsGFp::rfc6979(const QByteArray &hash, const ECInteger &x) const
{
    ECInteger q = this->N;
    QByteArray x_bytes = x.toQByteArray(true);
    int qbitlen = q.bitsLength();

    HMAC hmac = HMAC(QCryptographicHash::Sha256);
    QByteArray h1 = hash;
    QByteArray k = QByteArray(32, '\0');
    QByteArray v = QByteArray(32, 0x01);
    hmac.setKey(k);
    k = hmac(QByteArray().append(v).append(char(0x00)).append(x_bytes).append(h1));
    hmac.setKey(k);
    v = hmac(v);
    k = hmac(QByteArray().append(v).append(char(0x01)).append(x_bytes).append(h1));
    hmac.setKey(k);
    v = hmac(v);

    while(true){
        QByteArray t;
        while(t.size() < (qbitlen >> 3)){
            v = hmac(v);
            t.append(v);
        }
        ECInteger t_int(t.data(), qbitlen >> 3, 1, true);
        if(0 < t_int && t_int < q)
            return t_int;
        k = hmac(QByteArray().append(v).append(char(0x00)));
        hmac.setKey(k);
        v = hmac(v);
    }
}

ECInteger ECArithmeticsGFp::random(const QByteArray &hash, const ECInteger &x) const
{
    if(this->Deterministic)
        return this->rfc6979(hash, x);
    QCryptographicHash alg(QCryptographicHash::Sha256);
    alg.addData(hash);
    alg.addData(x.toQByteArray(true));
    DRBG drbg(alg.result(), 32);
    QByteArray bytes = drbg.generate(this->N.bytesLength());
    return ECInteger(bytes.data(), bytes.size(), 1, true);
}

void ECArithmeticsGFp::sign(const ECInteger &private_key, const ECInteger &e, ECInteger &r, ECInteger &s) const
{
    QByteArray msg = e.toQByteArray(true);
    r = ECInteger::zero();
    s = ECInteger::zero();
    ECInteger k = ECInteger::zero();
    ECInteger invK = ECInteger::zero();
    ECPoint m;

    while (s.isZero())
    {
        while (invK.isZero())
        {
            while (m.X.isZero())
            {
                k = this->random(msg, private_key);
                m = this->multiplication(this->G, k);
            }
            invK = ECInteger::modInverse(k, this->N);
        }
        m = this->jacobianToAffine(m);
        s = (invK * (e + m.X * private_key)) % this->N;
    }
    if(s.isNegative())
        s = (s + this->N) % this->N;
    r = m.X % this->N;
    if(r.isNegative())
        r = (r + this->N) % this->N;
}

bool ECArithmeticsGFp::verify(const ECPoint &public_key, const ECInteger &e, const ECInteger &r, const ECInteger &s) const
{
    if (s.isZero() || r.isZero())
        return false;

    ECInteger w = ECInteger::modInverse(s, this->N);
    ECInteger u1 = (e * w) % this->N;
    ECInteger u2 = (r * w) % this->N;

    ECPoint ss = this->jacobianToAffine(this->multiPointMultiplication(u1, this->G, u2, public_key));
    ECInteger v = ss.X % this->N;

    return v == r;
}

#include <sys/time.h>

bool ECArithmeticsGFp::test(bool show_parameters, int test_times, bool generate_pvk_per_test) const
{
    int byte_len = (this->BitLength + 7) >> 3;
    ECInteger e = ECInteger::random(byte_len) % this->N;
    ECInteger private_key = ECInteger::random(byte_len) % this->N;
    ECPoint public_key = this->jacobianToAffine(this->multiplication(this->G, private_key));

    timeval tvs, tve;
    ECInteger r, s;
    long total_sign_time = 0;
    long total_verify_time = 0;
    bool v = true;

    for(int i = 0; i < test_times && v; ++i){
        ::gettimeofday(&tvs, 0);
        this->sign(private_key, e, r, s);
        ::gettimeofday(&tve, 0);
        long sign_time = (tve.tv_sec - tvs.tv_sec) * 1000000L + (tve.tv_usec - tvs.tv_usec); //microsecond
        total_sign_time += sign_time;

        ::gettimeofday(&tvs, 0);
        v = this->verify(public_key, e, r, s);
        ::gettimeofday(&tve, 0);
        long verify_time = (tve.tv_sec - tvs.tv_sec) * 1000000L + (tve.tv_usec - tvs.tv_usec); //microsecond
        total_verify_time += verify_time;

        if(generate_pvk_per_test && v){
            e = ECInteger::random(byte_len) % this->N;
            private_key = ECInteger::random(byte_len) % this->N;
            public_key = this->jacobianToAffine(this->multiplication(this->G, private_key));
        }
    }

    if(show_parameters)
    {
        qDebug() << "Private Key:" << private_key.toQString();
        qDebug() << "Public Key:" << public_key.toQString();
        qDebug() << "Message:" << e.toQString();
        qDebug() << "Random R:" << r.toQString();
        qDebug() << "Signature:" << s.toQString();
        qDebug() << "Sign Time:" << total_sign_time / test_times << "us";
        qDebug() << "Verify Time:" << total_verify_time / test_times << "us";
    }
    return v;
}

//int main()
//{
//    bool show = true;
//    int test = 1000;
//    bool gen = true;

//    ECArithmeticsGFp secp112r1(ECC::CURVE_SECP112R1);
//    qDebug() << "SECP112R1:" << secp112r1.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp112r2(ECC::CURVE_SECP112R2);
//    qDebug() << "SECP112R2:" << secp112r2.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp128r1(ECC::CURVE_SECP128R1);
//    qDebug() << "SECP128R1:" << secp128r1.test(show, test, gen) << "\n";

//    ECArithmeticsGFp secp128r2(ECC::CURVE_SECP128R2);
//    qDebug() << "SECP128R2:" << secp128r2.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp160k1(ECC::CURVE_SECP160K1);
//    qDebug() << "SECP160K1:" << secp160k1.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp160r1(ECC::CURVE_SECP160R1);
//    qDebug() << "SECP160R1:" << secp160r1.test(show, test, gen) << "\n";

//    ECArithmeticsGFp secp160r2(ECC::CURVE_SECP160R2);
//    qDebug() << "SECP160R2:" << secp160r2.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp192k1(ECC::CURVE_SECP192K1);
//    qDebug() << "SECP192K1:" << secp192k1.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp192r1(ECC::CURVE_SECP192R1);
//    qDebug() << "SECP192R1:" << secp192r1.test(show, test, gen) << "\n";

//    ECArithmeticsGFp secp224k1(ECC::CURVE_SECP224K1);
//    qDebug() << "SECP224K1:" << secp224k1.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp224r1(ECC::CURVE_SECP224R1);
//    qDebug() << "SECP224R1:" << secp224r1.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp256k1(ECC::CURVE_SECP256K1);
//    qDebug() << "SECP256K1:" << secp256k1.test(show, test, gen) << "\n";

//    ECArithmeticsGFp secp256r1(ECC::CURVE_SECP256R1);
//    qDebug() << "SECP256R1:" << secp256r1.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp384r1(ECC::CURVE_SECP384R1);
//    qDebug() << "SECP384R1:" << secp384r1.test(show, test, gen) << "\n";
//    ECArithmeticsGFp secp521r1(ECC::CURVE_SECP521R1);
//    qDebug() << "SECP521R1:" << secp521r1.test(show, test, gen) << "\n";

//    return 0;
//}
