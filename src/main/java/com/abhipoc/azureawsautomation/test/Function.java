package com.abhipoc.azureawsautomation.test;

import com.azure.security.keyvault.secrets.SecretClient;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.securityhub.SecurityHubClient;
import software.amazon.awssdk.services.securityhub.model.AwsSecurityFinding;
import software.amazon.awssdk.services.securityhub.model.AwsSecurityFindingFilters;
import software.amazon.awssdk.services.securityhub.model.AwsSecurityFindingIdentifier;
import software.amazon.awssdk.services.securityhub.model.BatchUpdateFindingsRequest;
import software.amazon.awssdk.services.securityhub.model.BatchUpdateFindingsResponse;
import software.amazon.awssdk.services.securityhub.model.GetFindingsRequest;
import software.amazon.awssdk.services.securityhub.model.GetFindingsResponse;
import software.amazon.awssdk.services.securityhub.model.SecurityHubException;
import software.amazon.awssdk.services.securityhub.model.StringFilter;
import software.amazon.awssdk.services.securityhub.model.UpdateFindingsRequest;
import software.amazon.awssdk.services.securityhub.model.Workflow;
import software.amazon.awssdk.services.securityhub.model.WorkflowStatus;
import software.amazon.awssdk.services.securityhub.model.WorkflowUpdate;
import software.amazon.awssdk.services.securityhub.model.StringFilter.Builder;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;

/**
 * Azure Functions with HTTP Trigger.
 */
public class Function {
    /**
     * This function listens at endpoint "/api/HttpExample". Two ways to invoke it using "curl" command in bash:
     * 1. curl -d "HTTP Body" {your host}/api/HttpExample
     * 2. curl "{your host}/api/HttpExample?name=HTTP%20Query"
     */

    @FunctionName("HttpExample")
    public HttpResponseMessage run(
            @HttpTrigger(
                name  = "req",
                methods = {HttpMethod.GET, HttpMethod.POST},
                authLevel = AuthorizationLevel.ANONYMOUS)
                HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        // // Parse query parameter
        // final String query = request.getQueryParameters().get("name");
        // final String name = request.getBody().orElse(query);
        // if(name == null) {
        //     return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass a name on the query string or in the request body").build();
        // }
        // String rawARN = "arn:aws:securityhub:us-east-1:498227605698:subscription/aws-foundational-security-best-practices/v/1.0.0/Config.1/finding/9eb4cadd-b8e6-4afa-96ea-c0342984f14e";
        // String encodedARN = Base64.getEncoder().encodeToString(rawARN.getBytes());
        // System.out.println(encodedARN);

        // System.setProperty("aws.region", "us-east-1");
        // System.out.print(System.getProperty("aws.region"));       
        // AwsBasicCredentials awsCredentials = AwsBasicCredentials.create("AKIAXIAFN6DBA2TRV7FC", "k6knoP4YLrkvIuvBzdWKepZFoJOz7IZ1uDIl8bVN");
        // SecurityHubClient shc = SecurityHubClient.builder().credentialsProvider(StaticCredentialsProvider.create(awsCredentials)).build();
        // String findingUniqueARN = "arn:aws:securityhub:us-east-1:498227605698:subscription/aws-foundational-security-best-practices/v/1.0.0/Config.1/finding/9eb4cadd-b8e6-4afa-96ea-c0342984f14e";
        // StringFilter filter = StringFilter.builder().comparison("EQUALS").value(findingUniqueARN).build();
        // Collection<StringFilter> listFilters = new ArrayList<>();
        // listFilters.add(filter);
        // AwsSecurityFindingFilters filters = AwsSecurityFindingFilters.builder().id(listFilters).build();
        // GetFindingsRequest fro = GetFindingsRequest.builder().filters(filters).build();
        // software.amazon.awssdk.services.securityhub.model.GetFindingsResponse findingsResponse = shc.getFindings(fro);
        // //software.amazon.awssdk.services.securityhub.model.GetFindingsResponse findingsResponse =  shc.getFindings();    
        // List<AwsSecurityFinding> findings =   findingsResponse.findings();
        // Gson gson01 = new Gson();
        // String json01 = gson01.toJson(findings);
        // Gson gson2 = new Gson();
        // JsonArray ja = gson2.fromJson(json01, JsonArray.class);
        // JsonObject jo = ja.get(0).getAsJsonObject();
        // String productArn = jo.get("productArn").getAsString();
        // context.getLogger().info(json01);
        // try {
        //     AwsSecurityFindingIdentifier awsSecurityFindingIdentifier = AwsSecurityFindingIdentifier.builder().id(findingUniqueARN).productArn(productArn).build();
        //     Collection<AwsSecurityFindingIdentifier> fi = new ArrayList<>();
        //     fi.add(awsSecurityFindingIdentifier);
        //     WorkflowUpdate wu = WorkflowUpdate.builder().status(WorkflowStatus.RESOLVED).build();
        //     BatchUpdateFindingsRequest batchUpdateFindingsRequest = BatchUpdateFindingsRequest.builder().findingIdentifiers(fi).workflow(wu).build();
        //     shc.batchUpdateFindings(batchUpdateFindingsRequest);
            
        // } catch(Exception e) {
        //     context.getLogger().info(e.getMessage());
        // }
        
        // return request.createResponseBuilder(HttpStatus.OK).body(json01).build();

        try {
            final String query = request.getQueryParameters().get("id");
            final String findingId = request.getBody().orElse(query);
            JsonObject responseObj = new JsonObject();
            if(findingId == null) {
                throw new MalformedURLException();
            } 
            System.setProperty("aws.region", "us-east-1");
            // String accessKeyId = secretClient.getSecret("aws-security-account-iam-user-accessKeyId").getValue();
            // context.getLogger().info(accessKeyId);
            // String secretAccessKey = secretClient.getSecret("aws-security-account-iam-user-secretAccessKey").getValue(); 
            // context.getLogger().info(secretAccessKey);
            
            AwsBasicCredentials awsCredentials = AwsBasicCredentials.create("AKIAXIAFN6DBA2TRV7FC", "k6knoP4YLrkvIuvBzdWKepZFoJOz7IZ1uDIl8bVN");
            
            //AwsBasicCredentials awsCredentials = AwsBasicCredentials.create(accessKeyId, secretAccessKey);
            SecurityHubClient shc = SecurityHubClient.builder().credentialsProvider(StaticCredentialsProvider.create(awsCredentials)).build();
            StringFilter strFilter = StringFilter.builder().comparison("EQUALS").value(findingId).build();
            Collection<StringFilter> strFilterList = new ArrayList<>();
            strFilterList.add(strFilter);
            AwsSecurityFindingFilters awsSecurityFindingfilters = AwsSecurityFindingFilters.builder().id(strFilterList).build();

            //Building Get Finding Request
            GetFindingsRequest getFindingRequest = GetFindingsRequest.builder().filters(awsSecurityFindingfilters).build();
            software.amazon.awssdk.services.securityhub.model.GetFindingsResponse findingsResponse = shc.getFindings(getFindingRequest);
            
            List<AwsSecurityFinding> findings = findingsResponse.findings();
            if(findings.size() < 1) {
                throw new Exception("Unable to get any findings based on the findingId provided by SIEM");
            } 
            JsonArray findingsJsonArrayObj = new Gson().fromJson(new Gson().toJson(findings), JsonArray.class);
            JsonObject findingJsonObject = findingsJsonArrayObj.get(0).getAsJsonObject();
            String productArn = findingJsonObject.get("productArn").getAsString();
            JsonObject workflowStatusObject = findingJsonObject.get("workflow").getAsJsonObject();
            String workflowStatusValue = workflowStatusObject.get("status").getAsString();
            if(workflowStatusValue.equalsIgnoreCase("Resolved")) {
                responseObj.addProperty("Status", "Success");
                responseObj.addProperty("Message", "This finding is already closed");
                responseObj.addProperty("Details", "This finding must have been closed from Security Hub directly");
            }

            
            AwsSecurityFindingIdentifier awsSecurityFindingIdentifier = AwsSecurityFindingIdentifier.builder().id(findingId).productArn(productArn).build();
            Collection<AwsSecurityFindingIdentifier> awsSecurityFindingIdentifiersList = new ArrayList<>();
            awsSecurityFindingIdentifiersList.add(awsSecurityFindingIdentifier);
            WorkflowUpdate wu = WorkflowUpdate.builder().status(WorkflowStatus.RESOLVED).build();
            BatchUpdateFindingsRequest batchUpdateFindingsRequest = BatchUpdateFindingsRequest.builder().findingIdentifiers(awsSecurityFindingIdentifiersList).workflow(wu).build();
            shc.batchUpdateFindings(batchUpdateFindingsRequest);

            software.amazon.awssdk.services.securityhub.model.GetFindingsResponse updatedFindingsResponse = shc.getFindings(getFindingRequest);
            List<AwsSecurityFinding> updatedFindings = updatedFindingsResponse.findings();

            if(updatedFindings.size() < 1) {
                throw new Exception("Unable to get any findings based on the findingId provided by SIEM");
            } 
            JsonArray updatedFindingsJsonArrayObj = new Gson().fromJson(new Gson().toJson(updatedFindings), JsonArray.class);
            JsonObject updatedfindingJsonObject = updatedFindingsJsonArrayObj.get(0).getAsJsonObject();
            JsonObject updatedWorkflowStatusObject = updatedfindingJsonObject.get("workflow").getAsJsonObject();
            String updatedWorkflowStatusValue = updatedWorkflowStatusObject.get("status").getAsString();
            if(updatedWorkflowStatusValue.equalsIgnoreCase("Resolved")) {
                responseObj.addProperty("Status", "Success");
                responseObj.addProperty("Message", "This finding has been successfully closed");
                responseObj.addProperty("Details", "This finding has been closed at Security Hub by splunk/sentinal automation");
            }
            return request.createResponseBuilder(HttpStatus.OK).body(responseObj).build();
        } catch(MalformedURLException e) {
           JsonObject errorResponseObject = new JsonObject();
           context.getLogger().info(e.getMessage());
           errorResponseObject.addProperty("Status", "Failed");
           errorResponseObject.addProperty("Message", "Invalid Request, The request did not contain valid query parameters"); 
           errorResponseObject.addProperty("Details", "Missing findingId in the request query parameter");
           return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body(errorResponseObject).build();
        } catch(SecurityHubException e) {
           JsonObject errorResponseObject = new JsonObject();
           context.getLogger().info(e.getMessage());
           errorResponseObject.addProperty("Status", "Failed");
           errorResponseObject.addProperty("Message", "Invalid Request, The request did not contain valid query parameters"); 
           errorResponseObject.addProperty("Details", "Missing findingId in the request query parameter");
           return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponseObject).build();
        } catch(Exception e) {
           JsonObject errorResponseObject = new JsonObject();
           context.getLogger().info(e.getMessage());
           errorResponseObject.addProperty("Status", "Failed");
           errorResponseObject.addProperty("Message", "Invalid Request, The request did not contain valid query parameters"); 
           errorResponseObject.addProperty("Details", e.getLocalizedMessage());
           return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponseObject).build();
        }
    }

    
}
