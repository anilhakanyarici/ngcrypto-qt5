#include "hmac.h"

struct HMAC::pimpl
{
    QByteArray _m;
    QByteArray _k;
    int block_len;
    QCryptographicHash::Algorithm algorithm;
};

HMAC::HMAC(QCryptographicHash::Algorithm alg, const QByteArray &key)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->block_len = 64;
    this->_pimpl->algorithm = alg;
    this->setKey(key);
}

const QByteArray &HMAC::key() const
{
    return this->_pimpl->_k;
}

void HMAC::setKey(const QByteArray &key)
{
    this->_pimpl->_k = key;
}

QByteArray HMAC::operator ()(const QByteArray &m) const
{
    QCryptographicHash alg(this->_pimpl->algorithm);
    QByteArray ipad(this->_pimpl->block_len, 0x36);
    QByteArray opad(this->_pimpl->block_len, 0x5c);
    int output_len = QCryptographicHash::hashLength(this->_pimpl->algorithm);

    QByteArray key_prime(this->_pimpl->block_len, '\0');
    if(this->_pimpl->_k.size() > this->_pimpl->block_len)
    {
        QByteArray key_hash = QCryptographicHash::hash(this->_pimpl->_k, this->_pimpl->algorithm);
        ::memcpy(key_prime.data(), key_hash.data(), output_len);
    }
    else ::memcpy(key_prime.data(), this->_pimpl->_k.data(), this->_pimpl->_k.size());


    QByteArray ko(opad);
    for(int i = 0; i < this->_pimpl->block_len; ++i)
        ko[i] = ko[i] ^ key_prime[i];

    QByteArray ki(ipad);
    for(int i = 0; i < this->_pimpl->block_len; ++i)
        ki[i] = ki[i] ^ key_prime[i];

    alg.addData(ki);
    alg.addData(m);
    QByteArray h2 = alg.result();
    alg.reset();
    alg.addData(ko);
    alg.addData(h2);
    return alg.result();
}

void HMAC::addData(const QByteArray &data)
{
    this->_pimpl->_m.append(data);
}

QByteArray HMAC::result()
{
    return this->operator ()(this->_pimpl->_m);
}

void HMAC::reset()
{
    this->_pimpl->_m.clear();
}

