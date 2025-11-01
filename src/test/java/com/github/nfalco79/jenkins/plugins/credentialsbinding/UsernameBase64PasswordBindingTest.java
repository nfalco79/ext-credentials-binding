/*
 * Copyright 2021 Falco Nikolas
 * Licensed under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.github.nfalco79.jenkins.plugins.credentialsbinding;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.assertj.core.api.Assertions;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlPage;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.SecretBuildWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.xmlunit.assertj.XmlAssert;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsParameterDefinition;
import com.cloudbees.plugins.credentials.CredentialsParameterValue;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;

import hudson.Functions;
import hudson.Util;
import hudson.model.Fingerprint;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.ParametersAction;
import hudson.model.ParametersDefinitionProperty;
import hudson.remoting.Future;
import hudson.tasks.BatchFile;
import hudson.tasks.Shell;
import jenkins.model.Jenkins;

@WithJenkins
public class UsernameBase64PasswordBindingTest {

    private static JenkinsRule r;
    private CredentialsStore store = null;

    @BeforeAll
    static void init(JenkinsRule rule) {
        r = rule;
    }

    @Test
    void basics() throws Exception {
        String username = "bob";
        String password = "s3cr3t";
        UsernamePasswordCredentialsImpl c = new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, null, "sample", username, password);
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
        FreeStyleProject p = r.createFreeStyleProject();
        MultiBinding<?> binding = new UsernameBase64PasswordBinding("USER", "PASSWORD", c.getId());
        p.getBuildWrappersList().add(new SecretBuildWrapper(Collections.<MultiBinding<?>> singletonList(binding)));
        p.getBuildersList().add(Functions.isWindows() ? new BatchFile("echo %USER% > user.txt") : new Shell("echo $USER > user.txt"));
        p.getBuildersList().add(Functions.isWindows() ? new BatchFile("echo %PASSWORD% > pwd.txt") : new Shell("echo $PASSWORD > pwd.txt"));
        r.configRoundtrip(p);
        SecretBuildWrapper wrapper = p.getBuildWrappersList().get(SecretBuildWrapper.class);
        assertThat(wrapper).isNotNull();
        List<? extends MultiBinding<?>> bindings = wrapper.getBindings();
        assertThat(bindings).hasSize(1);
        binding = bindings.get(0);
        assertThat(binding.getCredentialsId()).isEqualTo(c.getId());
        assertThat(binding).isInstanceOf(UsernameBase64PasswordBinding.class);
        assertThat(((UsernameBase64PasswordBinding) binding).getUsernameVariable()).isEqualTo("USER");
        assertThat(((UsernameBase64PasswordBinding) binding).getPasswordVariable()).isEqualTo("PASSWORD");
        FreeStyleBuild b = r.buildAndAssertSuccess(p);
        r.assertLogNotContains(password, b);
        String bindingValue = b.getWorkspace().child("user.txt").readToString().trim();
        assertThat(bindingValue).isEqualTo(username);
        bindingValue = b.getWorkspace().child("pwd.txt").readToString().trim();
        assertThat(Base64.getEncoder().encodeToString(password.getBytes())).isEqualTo(bindingValue);
        assertThat(b.getSensitiveBuildVariables()).contains("PASSWORD");
    }

    @Test
    void theSecretBuildWrapperTracksUsage() throws Exception {
        SystemCredentialsProvider.getInstance().setDomainCredentialsMap(Collections.singletonMap(Domain.global(), Collections.<Credentials> emptyList()));
        for (CredentialsStore s : CredentialsProvider.lookupStores(Jenkins.get())) {
            if (s.getProvider() instanceof SystemCredentialsProvider.ProviderImpl) {
                store = s;
                break;
            }
        }
        Assertions.assertThat(store).as("The system credentials provider is enabled").isNotNull();

        UsernamePasswordCredentialsImpl credentials = new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, "secret-id", "test credentials", "bob", "secret");
        store.addCredentials(Domain.global(), credentials);

        Fingerprint fingerprint = CredentialsProvider.getFingerprintOf(credentials);
        Assertions.assertThat(fingerprint).as("No fingerprint created until first use").isNull();

        JenkinsRule.WebClient wc = r.createWebClient();
        HtmlPage page = wc.goTo("credentials/store/system/domain/_/credentials/secret-id");
        assertThat(page.getElementById("usage")).describedAs("Have usage tracking reported").isNotNull();
        assertThat(page.getElementById("usage-missing")).describedAs("No fingerprint created until first use").isNotNull();
        assertThat(page.getElementById("usage-present")).describedAs("No fingerprint created until first use").isNull();

        FreeStyleProject job = r.createFreeStyleProject();
        // add a parameter
        job.addProperty(new ParametersDefinitionProperty(new CredentialsParameterDefinition("SECRET", "The secret", "secret-id", Credentials.class.getName(), false)));

        r.assertBuildStatusSuccess((Future) job.scheduleBuild2(0, new ParametersAction(new CredentialsParameterValue("SECRET", "secret-id", "The secret", true))));

        fingerprint = CredentialsProvider.getFingerprintOf(credentials);
        assertThat(fingerprint).describedAs("A job that does nothing does not use parameterized credentials").isNull();

        page = wc.goTo("credentials/store/system/domain/_/credentials/secret-id");
        assertThat(page.getElementById("usage")).describedAs("Have usage tracking reported").isNotNull();
        assertThat(page.getElementById("usage-missing")).describedAs("No fingerprint created until first use").isNotNull();
        assertThat(page.getElementById("usage-present")).describedAs("No fingerprint created until first use").isNull();

        // check that the wrapper works as expected
        MultiBinding<?> binding = new UsernameBase64PasswordBinding("USER", "PASSWORD", credentials.getId());
        job.getBuildWrappersList().add(new SecretBuildWrapper(Collections.<MultiBinding<?>> singletonList(binding)));

        r.assertBuildStatusSuccess((Future) job.scheduleBuild2(0, new ParametersAction(new CredentialsParameterValue("SECRET", "secret-id", "The secret", true))));

        fingerprint = CredentialsProvider.getFingerprintOf(credentials);
        assertThat(fingerprint).isNotNull();
        assertThat(fingerprint.getJobs()).contains(job.getFullName());
        Fingerprint.RangeSet rangeSet = fingerprint.getRangeSet(job);
        assertThat(rangeSet).isNotNull();
        assertThat(rangeSet.includes(job.getLastBuild().getNumber())).isTrue();

        page = wc.goTo("credentials/store/system/domain/_/credentials/secret-id");
        assertThat(page.getElementById("usage-missing")).isNull();
        assertThat(page.getElementById("usage-present")).isNotNull();
        assertThat(page.getAnchorByText(job.getFullDisplayName())).isNotNull();

        // check the API
        WebResponse response = wc.goTo("credentials/store/system/domain/_/credentials/secret-id/api/xml?depth=1&xpath=*/fingerprint/usage", "application/xml").getWebResponse();
        XmlAssert.assertThat(response.getContentAsString()).and("<usage>"
                + "<name>" + Util.xmlEscape(job.getFullName()) + "</name>"
                + "<ranges>"
                + "<range>"
                + "<end>" + (job.getLastBuild().getNumber() + 1) + "</end>"
                + "<start>" + job.getLastBuild().getNumber() + "</start>"
                + "</range>"
                + "</ranges>"
                + "</usage>")
            .ignoreWhitespace()
            .ignoreComments()
            .areSimilar();
    }
}
