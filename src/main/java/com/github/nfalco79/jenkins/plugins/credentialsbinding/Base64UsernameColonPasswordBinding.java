/*
 * Copyright 2019 Falco Nikolas
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

import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.Binding;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;

public class Base64UsernameColonPasswordBinding extends Binding<StandardUsernamePasswordCredentials> {

    @DataBoundConstructor
    public Base64UsernameColonPasswordBinding(String variable, String credentialsId) {
        super(variable, credentialsId);
    }

    @Override
    protected Class<StandardUsernamePasswordCredentials> type() {
        return StandardUsernamePasswordCredentials.class;
    }

    @Override
    public SingleEnvironment bindSingle(@NonNull Run<?, ?> build, //
                                        @Nullable FilePath workspace, //
                                        @Nullable Launcher launcher, //
                                        @NonNull TaskListener listener) throws IOException, InterruptedException {
        StandardUsernamePasswordCredentials credentials = getCredentials(build);
        String usernameColumnPassword = credentials.getUsername() + ':' + credentials.getPassword().getPlainText();
        return new SingleEnvironment(Base64.getEncoder().encodeToString(usernameColumnPassword.getBytes("UTF-8")));
    }

    @Symbol("base64UsernameColonPassword")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<StandardUsernamePasswordCredentials> {

        @Override
        protected Class<StandardUsernamePasswordCredentials> type() {
            return StandardUsernamePasswordCredentials.class;
        }

        @Override
        public String getDisplayName() {
            return Messages.Base64UsernameColonPasswordBinding_displayName();
        }

        @Override
        public boolean requiresWorkspace() {
            return false;
        }
    }

}
