<?php

namespace Mdanter\X509\Certificates;

use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\X509\SignatureAlgorithm;

class CertificateInfo
{
    /**
     * @var int
     */
    private $serialNo;

    /**
     * @var SignatureAlgorithm
     */
    private $sigAlg;

    /**
     * @var CertificateSubject
     */
    private $issuer;

    /**
     * @var CertificateSubject
     */
    private $subject;

    /**
     * @var PublicKeyInterface
     */
    private $publicKey;

    /**
     * @var \DateTime
     */
    private $validityStart;

    /**
     * @var \DateTime
     */
    private $validityEnd;

    /**
     * @param int $serialNo
     * @param SignatureAlgorithm $sigAlgo
     * @param CertificateSubject $issuer
     * @param CertificateSubject $subject
     * @param PublicKeyInterface $publicKey
     * @param \DateTime $validityStart
     * @param \DateTime $validityEnd
     */
    public function __construct(
        $serialNo,
        SignatureAlgorithm $sigAlgo,
        CertificateSubject $issuer,
        CertificateSubject $subject,
        PublicKeyInterface $publicKey,
        \DateTime $validityStart,
        \DateTime $validityEnd
    ) {
        $this->serialNo = $serialNo;
        $this->sigAlg = $sigAlgo;
        $this->issuer = $issuer;
        $this->subject = $subject;
        $this->publicKey = $publicKey;
        $this->validityStart = $validityStart;
        $this->validityEnd = $validityEnd;
    }

    /**
     * @return int
     */
    public function getVersion()
    {
        // Implicit, so we need logic to work this out.
        return 1;
    }

    /**
     * @return int|string
     */
    public function getSerialNo()
    {
        return $this->serialNo;
    }

    /**
     * @return SignatureAlgorithm
     */
    public function getSigAlgorithm()
    {
        return $this->sigAlg;
    }

    /**
     * @return CertificateSubject
     */
    public function getIssuerInfo()
    {
        return $this->issuer;
    }

    /**
     * @return CertificateSubject
     */
    public function getSubjectInfo()
    {
        return $this->subject;
    }

    /**
     * @return PublicKeyInterface
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @return \DateTime
     */
    public function getValidityStart()
    {
        return $this->validityStart;
    }

    /**
     * @return \DateTime
     */
    public function getValidityEnd()
    {
        return $this->validityEnd;
    }
}
