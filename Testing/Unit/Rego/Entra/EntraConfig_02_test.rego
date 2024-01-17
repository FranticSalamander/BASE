package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.2.1v1
#--
test_MultifactorAuthentication_Correct_V1 if {
    PolicyId := "MS.Entra.2.1v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_MultifactorAuthentication_Correct_V2 if {
    PolicyId := "MS.Entra.2.1v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor",
                                            "deviceBasedPush"
                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
                "DisplayName":  "Passwordless MFA",
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_MultifactorAuthentication_Incorrect_V1 if {
    PolicyId := "MS.Entra.2.1v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,sofwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_MultifactorAuthentication_Incorrect_V2 if {
    PolicyId := "MS.Entra.2.1v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_MultifactorAuthentication_Incorrect_V3 if {
    PolicyId := "MS.Entra.2.1v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}
test_MultifactorAuthentication_Incorrect_V4 if {
    PolicyId := "MS.Entra.2.1v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password+ SMS",
                "DisplayName":  "Multifactor authentication"
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_MultifactorAuthentication_Incorrect_V5 if {
    PolicyId := "MS.Entra.2.1v1"

    Output := tests with input as {
        "authentication_strength_policy": [
             {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor",
                                            "deviceBasedPush"
                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
                "DisplayName":  "Passwordless MFA",
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }  
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

#
# MS.Entra.2.2v1
#--

test_PasswordlessMFA_Correct_V1 if {
    PolicyId := "MS.Entra.2.2v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor",
                                            "deviceBasedPush"
                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
                "DisplayName":  "Passwordless MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_PasswordlessMFA_Correct_V2 if {
    PolicyId := "MS.Entra.2.2v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor",
                                            "deviceBasedPush"
                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
                "DisplayName":  "Passwordless MFA",
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_PasswordlessMFA_Correct_V3 if { #Other settings being wrong should not effect the policy
    PolicyId := "MS.Entra.2.2v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertifcateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "pasword,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor",
                                            "deviceBasedPush"
                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
                "DisplayName":  "Passwordless MFA",
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_PasswordlessMFA_Incorrect_V1 if {
    PolicyId := "MS.Entra.2.2v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
                "DisplayName":  "Passwordless MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}
test_PasswordlessMFA_Incorrect_V2 if {
    PolicyId := "MS.Entra.2.2v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor",
                                            "deviceBasedPush"

                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_PasswordlessMFA_Incorrect_V3 if {
    PolicyId := "MS.Entra.2.2v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertifcateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "pasword,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}
#
# MS.Entra.2.3v1
#--


test_PhishingresistantMFA_Correct_V1 if {
    PolicyId := "MS.Entra.2.3v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_PhishingresistantMFA_Correct_V2 if {
    PolicyId := "MS.Entra.2.3v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                    "windowsHelloForBusiness",
                                    "fido2",
                                    "x509CertificateMultiFactor",
                                    "deviceBasedPush",
                                    "temporaryAccessPassOneTime",
                                    "temporaryAccessPassMultiUse",
                                    "password,microsoftAuthenticatorPush",
                                    "password,softwareOath",
                                    "password,hardwareOath",
                                    "password,sms",
                                    "password,voice",
                                    "federatedMultiFactor",
                                    "microsoftAuthenticatorPush,federatedSingleFactor",
                                    "softwareOath,federatedSingleFactor",
                                    "hardwareOath,federatedSingleFactor",
                                    "sms,federatedSingleFactor",
                                    "voice,federatedSingleFactor"
                                ],
                "Description":  "Combinations of methods that satisfy strong authentication, such as a password + SMS",
                "DisplayName":  "Multifactor authentication"
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor",
                                            "deviceBasedPush"
                                        ],
                "Description":  "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
                "DisplayName":  "Passwordless MFA",
            },
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_PhishingresistantMFA_Incorrect_V1 if {
    PolicyId := "MS.Entra.2.3v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido",
                                            "x509CertificateMultiFactor"
                                        ],
                "Description":  "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_PhishingresistantMFA_Incorrect_V2 if {
    PolicyId := "MS.Entra.2.3v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                "AllowedCombinations":  [
                                            "windowsHelloForBusiness",
                                            "fido2",
                                            "x509CertificateMultiFactor"
                                        ],
                "DisplayName":  "Phishing-resistant MFA",
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}

test_PhishingresistantMFA_Incorrect_V3 if {
    PolicyId := "MS.Entra.2.3v1"

    Output := tests with input as {
        "authentication_strength_policy": [
            {
                
            }
        ]
    }

    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met"
}