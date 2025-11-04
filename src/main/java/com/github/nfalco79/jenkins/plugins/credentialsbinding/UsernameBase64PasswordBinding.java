/*
 * Copyright 2019 Nikolas Falco
 *
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

import java.io.IOException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.impl.UsernamePasswordMultiBinding;
import org.kohsuke.stapler.DataBoundConstructor;

import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;

public class UsernameBase64PasswordBinding extends UsernamePasswordMultiBinding {

    @DataBoundConstructor
    public UsernameBase64PasswordBinding(String usernameVariable, String passwordVariable, String credentialsId) {
        super(usernameVariable, passwordVariable, credentialsId);
    }

    @Override
    public MultiEnvironment bind(Run<?, ?> build,
                                 FilePath workspace,
                                 Launcher launcher,
                                 TaskListener listener) throws IOException, InterruptedException {
        StandardUsernamePasswordCredentials credentials = getCredentials(build);
        Map<String, String> secretValues = new LinkedHashMap<>();
        Map<String, String> publicValues = new LinkedHashMap<>();
        (credentials.isUsernameSecret() ? secretValues : publicValues).put(getUsernameVariable(), credentials.getUsername());
        secretValues.put(getPasswordVariable(), Base64.getEncoder().encodeToString(credentials.getPassword().getPlainText().getBytes("UTF-8")));
        return new MultiEnvironment(secretValues, publicValues);
    }

    @Symbol("usernameBase64Password")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<StandardUsernamePasswordCredentials> {

        @Override
        protected Class<StandardUsernamePasswordCredentials> type() {
            return StandardUsernamePasswordCredentials.class;
        }

        @Override
        public String getDisplayName() {
            return Messages.UsernameBase64PasswordBinding_displayName();
        }

        @Override
        public boolean requiresWorkspace() {
            return false;
        }
    }


}
