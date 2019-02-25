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

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.criteria.DistinctLDiversity;
import org.deidentifier.arx.criteria.EnhancedBLikeness;
import org.deidentifier.arx.criteria.HierarchicalDistanceTCloseness;
import org.deidentifier.arx.criteria.KAnonymity;
import org.deidentifier.arx.criteria.PrivacyCriterion;

/**
 * Setup
 * 
 * @author Fabian Prasser
 */
public class BenchmarkSetup {

    /**
     * Benchmark privacy model
     * 
     * @author Fabian Prasser
     */
    public static enum BenchmarkPrivacyModel {
                                         K_ANONYMITY {
                                             @Override
                                             public String toString() {
                                                 return "K_ANONYMITY";
                                             }
                                         },
                                         T_CLOSENESS {
                                             @Override
                                             public String toString() {
                                                 return "T_CLOSENESS";
                                             }
                                         },
                                         ENHANCED_B_LIKENESS {
                                             @Override
                                             public String toString() {
                                                 return "ENHANCED_B_LIKENESS";
                                             }
                                         },
                                         DISTINCT_L_DIVERSITY {
                                             @Override
                                             public String toString() {
                                                 return "DISTINCT_L_DIVERSITY";
                                             }
                                         },
    }

    
    /**
     * Benchmark dataset
     * 
     * @author Fabian Prasser
     */
    public static enum BenchmarkDataset {
                                         CENSUS {
                                             @Override
                                             public String toString() {
                                                 return "Census";
                                             }
                                         },
                                         HEALTH {
                                             @Override
                                             public String toString() {
                                                 return "Health interviews";
                                             }
                                         }
    }

    /** Config */
    static final String RESULTS_FILENAME = "results/results.csv";    
    
    /** Config*/
    static final int LOCAL_ITERATIONS = 100;

    /**
     * Returns all class-attributes for this dataset
     * 
     * @param dataset
     * @return
     */
    public static String[] getSensitiveAttributes(BenchmarkDataset dataset) {
        switch (dataset) {
        case CENSUS:
            return new String[] {"Marital status", "Education"};
        case HEALTH:
            return new String[] {"MARSTAT", "EDUC"};
        default:
            throw new RuntimeException("Invalid dataset");
        }
    }

    /**
     * Configures and returns the dataset
     * 
     * @param dataset
     * @return
     * @throws IOException
     */
    public static Data getData(BenchmarkDataset dataset) throws IOException {
        Data data = null;
        switch (dataset) {
        case CENSUS:
            data = Data.create("data/ss13acs.csv", StandardCharsets.UTF_8, ';');
            break;
        case HEALTH:
            data = Data.create("data/ihis.csv", StandardCharsets.UTF_8, ';');
            break;
        default:
            throw new RuntimeException("Invalid dataset");
        }

        for (String qi : getQuasiIdentifyingAttributes(dataset)) {
            data.getDefinition().setAttributeType(qi, getHierarchy(dataset, qi));
        }

        return data;
    }

    /**
     * Returns the generalization hierarchy for the dataset and attribute
     * 
     * @param dataset
     * @param attribute
     * @return
     * @throws IOException
     */
    public static Hierarchy getHierarchy(BenchmarkDataset dataset,
                                         String attribute) throws IOException {
        String prefix = "";
        switch (dataset) {
        case CENSUS:
            prefix = "hierarchies/ss13acs_hierarchy_";
            break;
        case HEALTH:
            prefix = "hierarchies/ihis_hierarchy_";
            break;
        default:
            throw new RuntimeException("Invalid dataset");
        }

        return Hierarchy.create(prefix + attribute + ".csv", StandardCharsets.UTF_8, ';');
    }

    /**
     * Returns the quasi-identifiers for the dataset
     * 
     * @param dataset
     * @return
     */
    public static String[] getQuasiIdentifyingAttributes(BenchmarkDataset dataset) {
        switch (dataset) {
        case CENSUS:
            return new String[] { "Sex",
                                  "Age",
                                  "Race"};
        case HEALTH:
            return new String[] { "SEX",
                                  "AGE",
                                  "RACEA"};
        default:
            throw new RuntimeException("Invalid dataset");
        }
    }

    /**
     * Thresholds
     * @param model
     * @param dataset
     * @param attribute
     * @return
     */
    public static double[] getThresholds(BenchmarkPrivacyModel model, BenchmarkDataset dataset, String attribute) {
        switch (model) {
        case K_ANONYMITY:
            return new double[] { 5d };
        case DISTINCT_L_DIVERSITY:
            switch (dataset) {
            case CENSUS: // "Marital status", "Education"
                if ("Marital status".equals(attribute))
                    return new double[]{1, 2, 3, 4, 5};
                else if ("Education".equals(attribute) ) {
                    return new double[]{1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 25};
                } else {
                    throw new IllegalArgumentException("Invalid attribute: " + attribute);
                }
            case HEALTH: // "MARSTAT", "EDUC"
                if ("MARSTAT".equals(attribute))
                    return new double[]{1, 2, 3, 4, 5, 6, 8, 10};
                else if ("EDUC".equals(attribute) ) {
                    return new double[]{1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 25};
                } else {
                    throw new IllegalArgumentException("Invalid attribute: " + attribute);
                }
            default:
                throw new IllegalArgumentException("Unknown dataset: " + dataset);
            }
        case T_CLOSENESS:
            return new double[]{1, 0.8, 0.6, 0.4, 0.2};
        case ENHANCED_B_LIKENESS:
            return new double[]{6, 5, 4, 3, 2, 1};
        default:
            throw new RuntimeException("Unknown privacy model: " + model);
        }
    }

    /**
     * Facade for configuration of privacy model
     * @param dataset
     * @param model
     * @param sensitive
     * @param threshold
     * @return
     * @throws IOException
     */
    public static PrivacyCriterion getPrivacyModel(BenchmarkDataset dataset,
                                                   BenchmarkPrivacyModel model,
                                                   String sensitive,
                                                   double threshold) throws IOException {
        switch (model) {
        case DISTINCT_L_DIVERSITY:
            return new DistinctLDiversity(sensitive, (int)threshold);
        case T_CLOSENESS:
            return new HierarchicalDistanceTCloseness(sensitive, threshold, getHierarchy(dataset, sensitive));
        case ENHANCED_B_LIKENESS:
            return new EnhancedBLikeness(sensitive, threshold);
        case K_ANONYMITY:
            return new KAnonymity((int)Math.ceil(threshold));
        default:
            throw new RuntimeException("Unknown privacy model");
        }
    }
}