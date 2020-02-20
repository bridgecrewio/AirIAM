[![Maintained by Bridgecrew.io](https://img.shields.io/badge/maintained%20by-bridgecrew.io-blueviolet)](https://bridgecrew.io)
[![code_coverage](https://raw.githubusercontent.com/bridgecrewio/AirIAM/master/coverage.svg?sanitize=true)](https://github.com/bridgecrewio/AirIAM/actions?query=workflow%3Acoverage)
![Terraform Version](https://img.shields.io/badge/tf-%3E%3D0.12.0-blue.svg)
![build](https://github.com/bridgecrewio/AirIAM/workflows/build-and-test/badge.svg)

# AirIAM
Automating, simplifying and least-privilege-ing complex existing AWS IAM resource mesh with terraform (IaC) 

![Airiam](https://www.syfy.com/sites/syfy/files/styles/2280x1280/public/2019/03/airiam_star_trek_disco1_header.jpg)
> Airiam was a female cyberneticly enhanced Human serving as an officer in the Federation Starfleet in the 23rd century until her death in 2257.

AirIAM migrates an existing account's AWS IAM configurations into terraform, allowing easier access 
management, enabling review process and rolling back bad configurations easily.
While at it, AirIAM also reduces unused permissions to make sure the environment is adherent
to the least-privilege principal.

 