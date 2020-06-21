# btc-hot-wallet
Spring Boot based hot wallet and payment implementation for BTC. Support both on-premise and on-cloud. If you want to support the project, please donate to the following BTC address: 3JYBBEXybHQZacUkwjiFBZpooDBwn9c1PD

## Setup Development Environment
1. Install PostgreSQL and Java 8.
2. Create a new role. user name is "wallet", password is "password". Set the privileges to yes for all.
3. Create a new DB, name is "btcHotWallet", set the owner to the newly created role.
4. Run btc-hot-wallet-1.0.0-SNAPSHOT.jar by using "java -jar btc-hot-wallet-1.0.0-DEV.jar", Testnet will be used by default. If you want to run it on BTC mainnet, please use prod profile.
5. Copy the checkpoint file in etc folder to <user_home> folder if you want to accelarate the blockchain download speed.
6. When you see "All blocks have been downloaded. BTC wallet service is available." in your log, you system has started. It takes less than one minute if you use checkpoint. hours if not.
7. If you want to run it from eclipse or IntelliJ, sync the latest code, import the project and add btc-core-1.0.0.jar to local maven repo.

## REST API 
- **List all transactions:  GET** https://localhost:7000/api/v1/btc/wallet/bef1a9a4e39e4cb8b36be1ff9681529d/transaction/all?pageId=0&size=100

  example output:
  
  ```javascript
  {
  "size": 4,
  "transactions": [
    {
      "transactionId": "0d36b5e423ecd11178ff8e3a96ee9d8e426fc59a47bb9e4d7d709e60a8d82a4a",
      "status": "confirmed",
      "fee_string": "0",
      "created_date": "2020-06-01T17:12:34.290Z",
      "wallet_id": "bef1a9a4e39e4cb8b36be1ff9681529d",
      "transaction_type": "DEPOSIT",
      "outputs": [
        {
          "amount_string": "0.001",
          "amount_in_smallest_unit_string": "100000",
          "receive_address": "tb1qqnl2gmrjpdvztgvaf0lz5p5nn9ajawchydunr8",
          "index": 0
        }
      ]
    },
    {
      "transactionId": "d2286facfb391c5c0c3f2335fe8c7ff608c3c4bc0a1ef8a75d577c90de43583b",
      "status": "confirmed",
      "fee_string": "0",
      "created_date": "2020-06-01T17:14:14.680Z",
      "wallet_id": "bef1a9a4e39e4cb8b36be1ff9681529d",
      "transaction_type": "DEPOSIT",
      "outputs": [
        {
          "amount_string": "0.00899999",
          "amount_in_smallest_unit_string": "899999",
          "receive_address": "tb1qqnl2gmrjpdvztgvaf0lz5p5nn9ajawchydunr8",
          "index": 0
        }
      ]
    },
    {
      "transactionId": "a10c0bc2a7f6d8818b52cc9e9b09ce788835e5eda9728d5ed923dab726b4c6a9",
      "status": "confirmed",
      "fee_string": "0",
      "created_date": "2020-06-02T17:34:02.681Z",
      "wallet_id": "bef1a9a4e39e4cb8b36be1ff9681529d",
      "transaction_type": "DEPOSIT",
      "outputs": [
        {
          "amount_string": "0.00778237",
          "amount_in_smallest_unit_string": "778237",
          "receive_address": "tb1q6ksyc4gk7h87vdxp0zgtdn7tnmdepyf7ppwafg",
          "index": 0
        }
      ]
    },
    {
      "transactionId": "c2626cf3d3d06faf2b24ff4ab9b5e0fa89c75b1d094c0d92b6eacb7c858f28a2",
      "status": "confirmed",
      "fee_string": "6102",
      "created_date": "2020-06-02T17:38:54.007Z",
      "wallet_id": "bef1a9a4e39e4cb8b36be1ff9681529d",
      "transaction_type": "WITHDRAWAL",
      "outputs": [
        {
          "amount_string": "0.00118111",
          "amount_in_smallest_unit_string": "118111",
          "receive_address": "2NAark2jaY4GjKgpAFS4HQ1nQfReQad62wx",
          "index": 0
        }
      ]
    }
  ]
  }
  ```


- **Create wallet:  POST** https://hostname:7000/api/v1/btc/wallet/new

    wallet-per-user is supported. You can create one or multiple wallets for one user. Based on our performance test, each microservice should be able to support 200 wallet.
  
  example input:
  ```javascript
  {
  	"symbol": "BTC",
  	"label":"test wallet 001",
  	"enabled":true
  }
  ```
  
  example output:
  ```javascript
  {
    "id": "5bac703547754df7bce7840685436d4c",
    "enabled": true,
    "created_date": "2020-06-06T18:25:38.024Z",
    "encrypted_seed": "fkZNIEIJOSYj28+LIDoskWQ3igwJ40YxWKBJj0waYiLmG5ePkyur4w+sKYSCFYg7",
    "creation_time": 1591467938
  }
  ```

  
 - **Get wallet:  GET**  https://hostname:7000/api/v1/btc/wallet/{walletId}

    output example:
    ```javascript
        {
          "id": "bef1a9a4e39e4cb8b36be1ff9681529d",
          "enabled": true,
          "createdDate": "2020-06-01T21:03:38.290Z",
          "label": "test wallet 001",
          "balance": {
            "estimated": "0.00754024",
            "available": "0.00754024"
          }
        }
    ```

  - **List wallets:  GET**  https://hostname:7000/api/v1/btc/wallet/all?pageId=0&size=10

        output example:

        ```javascript
        {
        "wallets": [
          {
            "enabled": true,
            "createdDate": "2020-06-06T18:25:38.024Z",
            "label": "test wallet 001",
            "balance": {
              "estimated": "0",
              "available": "0"
            }
          },
          {
            "enabled": true,
            "createdDate": "2020-06-01T21:03:38.290Z",
            "label": "test wallet 001",
            "balance": {
              "estimated": "0.00754024",
              "available": "0.00754024"
            }
          },
          {
            "enabled": false,
            "createdDate": "2020-06-01T21:02:02.963Z",
            "label": "DEFAULT"
          }
        ]
        }
    ```

- **Generate receiving address:  POST**   https://hostname:7000/api/v1/btc/wallet/{walletId}/address/new

    example input:
    ```javascript
      {
        "symbol":"BTC",
        "label": "testing"
      }
  ```
  
  example output:
  ```javascript
  {
    "address": "tb1qgct8yqksmlmjwerp3keclkgncswj2f7su0la8j",
    "label": "testing"
  }
  ```

- **Get Balance:  GET**   https://hostname:7000/api/v1/btc/wallet/{walletId}}/balance

    example output:
    ```javascript
    {
      "id": "bef1a9a4e39e4cb8b36be1ff9681529d",
      "balance": {
        "estimated": "0.00754024",
        "available": "0.00754024"
      }
    }
    ```

- **Send coin directly:   POST**   https://hostname:9000/api/v1/btc/wallet/{walletId}/send

   example input:
    
   ```javascript
      {
       "symbol":"BTC",
       "internal_transaction_id": "testing",
       "number_block":6,
       "recipients":
       [
       	{
       		"address":"tb1qcfxn0t3htlufzq6xe5cgcl3g2r2590vpp64had",
       		"amount":"1133110"
       	},
       	{
       		"address":"2MzwkogEL5bQ2bGqfEtXtmQjB6PW6T79fhw",
       		"amount":"1122110"
       	}
       ]
       }
   ```
     
   example output:
   
   ```javascript
      {
        "transaction_id": "c2626cf3d3d06faf2b24ff4ab9b5e0fa89c75b1d094c0d92b6eacb7c858f28a2"
      }
   ```
