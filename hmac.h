#ifndef HMAC_H
#define HMAC_H

#include <QByteArray>
#include <QSharedPointer>
#include <QCryptographicHash>

//rfc2104
class HMAC
{
    struct pimpl;
    QSharedPointer<pimpl> _pimpl;

public:

    HMAC(QCryptographicHash::Algorithm alg = QCryptographicHash::Sha1, const QByteArray &key = QByteArray());

    const QByteArray &key() const;
    void setKey(const QByteArray &key);

    QByteArray operator ()(const QByteArray &m) const;

    void addData(const QByteArray &data);
    QByteArray result();
    void reset();
};

#endif // HMAC_H
