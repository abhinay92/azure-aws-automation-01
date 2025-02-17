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

        try {
            final String query = request.getQueryParameters().get("id");
            final String findingId = request.getBody().orElse(query);
            JsonObject responseObj = new JsonObject();
            if(findingId == null) {
                throw new MalformedURLException();
            } 
            System.setProperty("aws.region", "us-east-1");
            
            
            AwsBasicCredentials awsCredentials = AwsBasicCredentials.create("<ClientID>>", "<ClientSecret>");            
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
