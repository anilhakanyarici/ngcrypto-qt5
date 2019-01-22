#ifndef RFC2898GENERATOR_H
#define RFC2898GENERATOR_H

#include <QByteArray>
#include <QSharedPointer>

class Rfc2898Generator
{
    struct pimpl;
    QSharedPointer<pimpl> _pimpl;

public:
    enum DerivationFunction { PBKDF1, PBKDF2 };

    Rfc2898Generator(const QString &password, ulong salt, uint iterations = 1000, DerivationFunction function = Rfc2898Generator::PBKDF2);
    Rfc2898Generator(const QByteArray &password, ulong salt, uint iterations = 1000, DerivationFunction function = Rfc2898Generator::PBKDF2);

    ulong salt() const;
    void setSalt(ulong salt);
    uint iteration() const;
    void setIteration(uint iter);

    QByteArray generate(int cb);
    void reset();
};

#endif // RFC2898GENERATOR_H
