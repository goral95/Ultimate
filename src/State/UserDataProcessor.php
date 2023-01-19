<?php
namespace App\State;

use ApiPlatform\Metadata\DeleteOperationInterface;
use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProcessorInterface;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserDataProcessor implements ProcessorInterface
{

    /**
     * @var EntityManagerInterface $entityManagerInterface
     */
    private $entityManagerInterface;

    /**
     * @var UserPasswordHasherInterface $userPasswordHasherInterface
     */
    private $userPasswordHasherInterface;

    public function __construct(EntityManagerInterface $entityManagerInterface, UserPasswordHasherInterface $userPasswordHasherInterface){
        $this->entityManagerInterface = $entityManagerInterface;
        $this->userPasswordHasherInterface = $userPasswordHasherInterface;
    }

    /**
     * @param User $data
     */
    public function process(mixed $data, Operation $operation, array $uriVariables = [], array $context = [])
    {
        if ($operation instanceof DeleteOperationInterface) {
            $this->entityManagerInterface->remove($data);
            $this->entityManagerInterface->flush();
            return;
        }
        if($data->getPlainPassword()) {
            $data->setPassword(
                $this->userPasswordHasherInterface->hashPassword($data, $data->getPlainPassword())
            );

            $data->eraseCredentials();
        }
        $this->entityManagerInterface->persist($data);
        $this->entityManagerInterface->flush();
        return $data;
    }
}