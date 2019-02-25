/*
 * Attribute disclosure benchmark
 * Benchmark of methods for protecting data from attribute disclosure
 * 
 * Copyright (C) 2019 Helmut Spengler, Fabian Prasser
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package org.deidentifier.arx.benchmark;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;

import org.deidentifier.arx.ARXAnonymizer;
import org.deidentifier.arx.ARXClassificationConfiguration;
import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.ARXLattice.ARXNode;
import org.deidentifier.arx.ARXResult;
import org.deidentifier.arx.AttributeType;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.DataHandle;
import org.deidentifier.arx.aggregates.StatisticsClassification;
import org.deidentifier.arx.benchmark.BenchmarkSetup.BenchmarkDataset;
import org.deidentifier.arx.benchmark.BenchmarkSetup.BenchmarkPrivacyModel;
import org.deidentifier.arx.exceptions.RollbackRequiredException;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.metric.Metric.AggregateFunction;

import de.linearbits.subframe.Benchmark;
import de.linearbits.subframe.analyzer.ValueBuffer;

/**
 * Experiment
 * @author Helmut Spengler
 * @author Fabian Prasser
 */
public class Experiment {
    
    /** Benchmark*/
    private static final Benchmark benchmark = new Benchmark(new String[] {"dataset", "sensitive", "model", "threshold", "transformation"});
    /** Benchmark*/
    private static final int LOSS = benchmark.addMeasure("quality_loss");
    /** Benchmark*/
    private static final int ACCURACY_LR_ANON = benchmark.addMeasure("accuracy_lr_anon");


    /**
     * Main entry point for performing experiments
     * @throws IOException
     * @throws ParseException
     * @throws RollbackRequiredException
     */
    public static void main(String[] args) throws IOException, ParseException, RollbackRequiredException {
        
        // Prepare
        benchmark.addAnalyzer(ACCURACY_LR_ANON, new ValueBuffer());
        benchmark.addAnalyzer(LOSS, new ValueBuffer());

        // For each privacy model
        for (BenchmarkPrivacyModel model : BenchmarkPrivacyModel.values()) {

            // For each dataset
            for (BenchmarkDataset dataset : BenchmarkDataset.values()) {

                // For each sensitive attribute
                for (String attribute : BenchmarkSetup.getSensitiveAttributes(dataset)) {

                    // For each threshold
                    for (double threshold : BenchmarkSetup.getThresholds(model, dataset, attribute)) {

                        benchmark(dataset, model, attribute, threshold);
                    }
                }
            }
        }
    }


    /**
     * @param dataset
     * @param model
     * @param sensitive
     * @param threshold
     * @param fullLatticeScan
     * @throws IOException
     * @throws ParseException
     * @throws RollbackRequiredException 
     */
    private static void benchmark(BenchmarkDataset dataset, BenchmarkPrivacyModel model, String sensitive, double threshold) throws IOException, ParseException, RollbackRequiredException {

        Data data = configureData(dataset, sensitive, model);

        // Configure
        ARXAnonymizer anonymizer = new ARXAnonymizer();
        ARXConfiguration config = configureARX(model, dataset, sensitive, threshold);

        // Anonymize
        ARXResult result = anonymizer.anonymize(data, config);

        // For each level
        for (int level = 0; level <= result.getLattice()
                                          .getTop()
                                          .getTotalGeneralizationLevel(); level++) {
            
            // Obtain level
            ARXNode[] nodes = result.getLattice().getLevels()[level];
            
            // For each node on that level
            for (ARXNode node : nodes) {
                
                // Prepare iteration over next level
                node.expand();
            
                // Analyze node
              DataHandle output = result.getOutput(node, false);
              
              result.optimizeIterativeFast(output, 1d / (double)BenchmarkSetup.LOCAL_ITERATIONS);
              
              performMeasurements(dataset, model, sensitive, threshold, node, output);
            }
        }
    }


    private static void performMeasurements(BenchmarkDataset dataset,
                                            BenchmarkPrivacyModel model,
                                            String sensitive,
                                            double threshold,
                                            ARXNode node,
                                            DataHandle output) throws ParseException, IOException {
        // Measure
        System.out.println("Run: " + dataset+"/"+sensitive+"/"+model+"/"+threshold+"/"+Arrays.toString(node.getTransformation()));
        benchmark.addRun(dataset, sensitive, model, threshold, Arrays.toString(node.getTransformation()));

        // Classify and truncate - old variant
        StatisticsClassification stats = output.getStatistics().getClassificationPerformance(BenchmarkSetup.getQuasiIdentifyingAttributes(dataset),
                                                                                             sensitive,
                                                                                             ARXClassificationConfiguration.createLogisticRegression().setNumFolds(3).setMaxRecords(Integer.MAX_VALUE));
        
        // Analyze
        benchmark.addValue(LOSS, output.getStatistics().getQualityStatistics().getGranularity().getArithmeticMean());
        benchmark.addValue(ACCURACY_LR_ANON, stats.getAccuracy());

        output.release();
        benchmark.getResults().write(new File(BenchmarkSetup.RESULTS_FILENAME));
    }

    /**
     * Configure the dataset
     * @param dataset
     * @param sensitive
     * @param privacyModel
     * @return
     * @throws IOException
     */
    public static Data configureData(BenchmarkDataset dataset, String sensitive, BenchmarkPrivacyModel privacyModel) throws IOException {
        // Init
        Data data = BenchmarkSetup.getData(dataset);
        for (String attribute : BenchmarkSetup.getQuasiIdentifyingAttributes(dataset)) {
            data.getDefinition().setAttributeType(attribute, BenchmarkSetup.getHierarchy(dataset, attribute));
        }
        if (!BenchmarkPrivacyModel.K_ANONYMITY.equals(privacyModel)) {
            data.getDefinition().setAttributeType(sensitive, AttributeType.SENSITIVE_ATTRIBUTE);
        } else {
            data.getDefinition().setAttributeType(sensitive, AttributeType.INSENSITIVE_ATTRIBUTE);
        }
        data.getDefinition().setResponseVariable(sensitive, true);
        return data;
    }


    /**
     * Configure ARX
     * @param model
     * @param dataset
     * @param sensitive
     * @param threshold
     * @return
     * @throws IOException
     */
    public static ARXConfiguration configureARX(BenchmarkPrivacyModel model, BenchmarkDataset dataset, String sensitive, double threshold) throws IOException {
        
        // Create empty config
        ARXConfiguration config = ARXConfiguration.create();
        
        // Configre number of iterations for local generalization
        config.setSuppressionLimit(1d - (1d / (double)BenchmarkSetup.LOCAL_ITERATIONS));
        
        // Set loss as target function for optimization
        config.setQualityModel(Metric.createLossMetric(0d, AggregateFunction.ARITHMETIC_MEAN));
        
        // Perform detail configuration for privacy model
        config.addPrivacyModel(BenchmarkSetup.getPrivacyModel(dataset, model, sensitive, threshold));
        
        // always combine SA-models with 5-anonymity
        if (!BenchmarkPrivacyModel.K_ANONYMITY.equals(model)) {
            config.addPrivacyModel(BenchmarkSetup.getPrivacyModel(dataset, BenchmarkPrivacyModel.K_ANONYMITY, sensitive, 5d));
        }
        
        return config;
    }
}
