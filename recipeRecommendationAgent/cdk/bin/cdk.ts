#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { BaseStackProps } from '../lib/types';
import {
  DockerImageStack,
  AgentCoreStack
} from '../lib/stacks';

const app = new cdk.App();
const deploymentProps: BaseStackProps = {
  appName: "recipeRecommendationAgent",
  }
const dockerImageStack = new DockerImageStack(app, `recipeRecommendationAgent-DockerImageStack`, deploymentProps);
const agentCoreStack = new AgentCoreStack(app, `recipeRecommendationAgent-AgentCoreStack`, {
  ...deploymentProps,
  imageUri: dockerImageStack.imageUri
});
agentCoreStack.addDependency(dockerImageStack);