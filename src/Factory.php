<?php

namespace Mdanter\X509;

use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\MathAdapterInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\X509\Serializer\Certificates\CertificateSubjectSerializer;
use Mdanter\X509\Certificates\CertificateAuthority;
use Mdanter\X509\Certificates\CertificateSubject;
use Mdanter\X509\Certificates\Csr;

class Factory
{
    /**
     * @param MathAdapterInterface|null $adapter
     * @param string $curveName
     * @param string $hashAlgorithm
     * @return EcDomain
     */
    public static function getDomain(MathAdapterInterface $adapter, $curveName, $hashAlgorithm)
    {
        $adapter = $adapter ?: EccFactory::getAdapter();

        return new EcDomain(
            $adapter,
            CurveFactory::getCurveByName($curveName),
            CurveFactory::getGeneratorByName($curveName),
            new Hasher($adapter, $hashAlgorithm)
        );
    }

    /**
     * @param EcDomain $domain
     * @param CertificateSubject $subject
     * @param PrivateKeyInterface $privateKey
     * @return Csr
     */
    public static function getCsr(EcDomain $domain, CertificateSubject $subject, PrivateKeyInterface $privateKey)
    {
        $subjectSerializer = new CertificateSubjectSerializer();
        $serialized = $subjectSerializer->serialize($subject);

        return new Csr(
            $domain,
            $subject,
            $privateKey->getPublicKey(),
            $domain
                ->getSigner()
                ->sign(
                    $privateKey,
                    $domain
                        ->getHasher()
                        ->hashDec($serialized),
                    RandomGeneratorFactory::getUrandomGenerator()
                        ->generate($domain->getGenerator()->getOrder())
                )
        );
    }

    /**
     * @param MathAdapterInterface $math
     * @param EcDomain $domain
     * @param CertificateSubject $issuerSubject
     * @return CertificateAuthority
     */
    public static function getCA(MathAdapterInterface $math, EcDomain $domain, CertificateSubject $issuerSubject)
    {
        return new CertificateAuthority(
            $math,
            $domain,
            $issuerSubject
        );
    }
}
