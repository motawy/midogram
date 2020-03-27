
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIJIJvuZl9iOVUVMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNV
BAMTFWRldi1taWRvLmV1LmF1dGgwLmNvbTAeFw0yMDAzMjYyMjEyNTRaFw0zMzEy
MDMyMjEyNTRaMCAxHjAcBgNVBAMTFWRldi1taWRvLmV1LmF1dGgwLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL41avQi+ul2dIrHWzZWToc5r4fR
Z5aQXlG6Tp0ITva61lng4JBHnUY+yw78YC6f6EkeWg6KLGAfMXn9zzC6lejLvtbi
2x7a2//Q69Zyl4z3icEHB6XTfyNnMfd6v0N2hyFR3HNSXPFnZtMXNg/bmOG5S9E3
U7nBF8rHKwIgwVeIo5NYxDq3ryZzoY7nboCqZ+nHD1qxW8qqBYOo3zXgHDNruC6z
OJBJYal8oBE9MbWr+oct4psGoMZ/8ylzqn6u6kR3y6Fuqj5C1Vv7uKk7TSh9Rq77
Voc/89czVXTBJmjVeC6FDnFHjtiEDqMa7cigU8NzBvOJGm97nCumIek4VNkCAwEA
AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUAxWKQrCnY2JMJ/d6Inlq
7H7NHaYwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBrwNppAa1i
vIjpWXablQodmjRlgDpcVIdYZkAWc1rTeNcnXYF/oDlkxH2NLynK+KROyeQylUjj
5wMAUIveBcemFqgy0rwroED/4XTf9k+oBYdkgiBzvy3kBMq+L8rn2HSA+ujWWAG+
xLKFKSMcKN8LVtyGe51O0avqYqyXjj/yUl1BPzdMiumLZw1TGjzZ5y2gBKJOBATb
1wh3DSOsCtFajQHZMlATAzz3yrBCI+sE9Hw1Mpc9tSVYYtyQ9UQMXZKeb/JgwQg/
gww44mftj4xyIjDZV9+xdk7uOYpgxLP+hmNjgQimz85SSwY/SSChfbGqoTn4FUU/
+BZFF9D9nqFY
-----END CERTIFICATE-----
`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
    try {
        const jwtToken = verifyToken(event.authorizationToken)
        console.log('User was authorized', jwtToken)
        return {
            principalId: jwtToken.sub,
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: 'Allow',
                        Resource: '*'
                    }
                ]
            }
        }
    } catch (e) {
        console.log('User authorized', e.message)
        return {
            principalId: 'user',
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: 'Deny',
                        Resource: '*'
                    }
                ]
            }
        }
    }
}

function verifyToken(authHeader: string): JwtToken {
    if (!authHeader)
        throw new Error('No authentication header')
    if (!authHeader.toLowerCase().startsWith('bearer '))
        throw new Error('Invalid authentication header')
    const split = authHeader.split(' ')
    const token = split[1]
    return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
