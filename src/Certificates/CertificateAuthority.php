<?php

namespace Mdanter\X509\Certificates;

use Mdanter\Ecc\Math\MathAdapterInterface;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\X509\SignatureAlgorithm;
use Mdanter\X509\Serializer\Certificates\CertificateSerializer;
use Mdanter\X509\EcDomain;

class CertificateAuthority
{
    /**
     * @var MathAdapterInterface
     */
    private $math;

    /**
     * @var CertificateSubject
     */
    private $issuer;

    /**
     * @var SignatureAlgorithm
     */
    private $sigAlg;

    /**
     * @var EcDomain
     */
    private $domain;

    /**
     * @param MathAdapterInterface $math
     * @param EcDomain $domain
     * @param CertificateSubject $issuer
     */
    public function __construct(MathAdapterInterface $math, EcDomain $domain, CertificateSubject $issuer)
    {
        $this->math = $math;
        $this->domain = $domain;
        $this->issuer = $issuer;
    }

    /**
     * @param Csr $csr
     * @param int $serialNumber
     * @param \DateTime $validityStart
     * @param \DateTime $validityEnd
     * @return CertificateInfo
     */
    public function createCertificateInfo(Csr $csr, $serialNumber, \DateTime $validityStart, \DateTime $validityEnd)
    {
        return new CertificateInfo(
            $serialNumber,
            $this->sigAlg, // or csr
            $this->issuer,
            $csr->getSubject(),
            $csr->getPublicKey(),
            $validityStart,
            $validityEnd
        );
    }

    /**
     * @param CertificateSerializer $subjectSerializer
     * @param CertificateInfo $certificateInfo
     * @param PrivateKeyInterface $privateKey
     * @return Certificate
     */
    public function createCertificate(CertificateSerializer $subjectSerializer, CertificateInfo $certificateInfo, PrivateKeyInterface $privateKey)
    {
        $domain = $this->domain;
        $dataHex = $subjectSerializer->getSignatureData($certificateInfo);
        $hash = $domain->getHasher()->hashDec($dataHex);

        $rng = RandomGeneratorFactory::getUrandomGenerator();
        $k = $rng->generate($domain->getGenerator()->getOrder());
        $signature = $this->domain->getSigner()->sign($privateKey, $hash, $k);

        return new Certificate(
            $certificateInfo,
            $this->domain->getSigAlgorithm(),
            $signature
        );
    }
}
