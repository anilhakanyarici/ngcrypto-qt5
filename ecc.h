#ifndef ECC_H
#define ECC_H

#include <QByteArray>
#include <QSharedPointer>
#include <QCryptographicHash>

class ECC
{
    struct pimpl;
    QSharedPointer<pimpl> _pimpl;

public:
    enum CurveName { CURVE_SECP112R1, CURVE_SECP112R2,
                     CURVE_SECP128R1, CURVE_SECP128R2,
    CURVE_SECP160K1, CURVE_SECP160R1, CURVE_SECP160R2,
    CURVE_SECP192K1, CURVE_SECP192R1,
    CURVE_SECP224K1, CURVE_SECP224R1,
    CURVE_SECP256K1, CURVE_SECP256R1,
                     CURVE_SECP384R1,
                     CURVE_SECP521R1 };

    const QByteArray &privateKey() const;
    int signatureSize() const; //Byte Length of sign.
    int keySize() const; //Bit length of key.
    QCryptographicHash::Algorithm hashAlgorithm() const;
    void setHashAlgorithm(QCryptographicHash::Algorithm alg) const;
    bool isPrivate() const;
    bool isValid() const;

    ECC(const QByteArray &private_key = QByteArray(), CurveName name = CURVE_SECP256R1, bool deterministic = false);
    ECC(const QString &private_key, CurveName name = CURVE_SECP256R1, bool deterministic = false);

    static ECC withRandomPrivateKey(CurveName name = CURVE_SECP256R1, bool deterministic = false);
    static ECC withHexPrivateKey(const QString &hex, CurveName name = CURVE_SECP256R1, bool deterministic = false);

    QByteArray signData(const QByteArray &data) const;
    QByteArray signHash(const QByteArray &hash) const;
    bool verifyData(const QByteArray &data, const QByteArray &sign) const;
    bool verifyHash(const QByteArray &hash, const QByteArray &sign) const;

    QString to4050XmlString() const;
    static ECC from4050XmlString(const QString &rfc4050Xml);

    QByteArray keyExchange(const QString &other4050PublicKey) const;
};

#endif // ECC_H
