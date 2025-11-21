import { useState, useMemo, useCallback, useRef, useEffect } from 'react';

// Advanced data management hook for handling large datasets (1000+ records)
export const useAdvancedDataManagement = (
  initialData = [],
  options = {}
) => {
  const {
    chunkSize = 100,
    enableVirtualization = true,
    enableCaching = true,
    enableIndexing = true,
    searchFields = [],
    sortFields = [],
    filterFields = []
  } = options;

  // Core state management
  const [data, setData] = useState(initialData);
  const [filteredData, setFilteredData] = useState(initialData);
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({});
  const [sortConfig, setSortConfig] = useState({ field: null, direction: 'asc' });
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [loading, setLoading] = useState(false);
  const [selectedItems, setSelectedItems] = useState(new Set());

  // Stable references for arrays to prevent infinite re-renders
  const stableSearchFields = useMemo(() => searchFields, [JSON.stringify(searchFields)]);
  const stableSortFields = useMemo(() => sortFields, [JSON.stringify(sortFields)]);
  const stableFilterFields = useMemo(() => filterFields, [JSON.stringify(filterFields)]);

  // Performance optimization refs
  const searchIndexRef = useRef(new Map());
  const filterCacheRef = useRef(new Map());
  const sortCacheRef = useRef(new Map());
  const dataChunksRef = useRef([]);

  // Build search index for fast text searching
  const buildSearchIndex = useCallback((dataArray) => {
    if (!enableIndexing || !stableSearchFields.length) return;
    
    const index = new Map();
    dataArray.forEach((item, idx) => {
      const searchableText = stableSearchFields
        .map(field => getNestedValue(item, field))
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      
      // Create n-gram index for fast partial matching
      const words = searchableText.split(/\s+/);
      words.forEach(word => {
        if (word.length > 2) {
          for (let i = 0; i < word.length - 2; i++) {
            const ngram = word.slice(i, i + 3);
            if (!index.has(ngram)) {
              index.set(ngram, new Set());
            }
            index.get(ngram).add(idx);
          }
        }
      });
    });
    
    searchIndexRef.current = index;
  }, [stableSearchFields, enableIndexing]);

  // Helper function to get nested object values
  const getNestedValue = useCallback((obj, path) => {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }, []);

  // Chunk data for better memory management
  const chunkData = useCallback((dataArray) => {
    const chunks = [];
    for (let i = 0; i < dataArray.length; i += chunkSize) {
      chunks.push(dataArray.slice(i, i + chunkSize));
    }
    dataChunksRef.current = chunks;
    return chunks;
  }, [chunkSize]);

  // Fast search using index
  const searchData = useCallback((dataArray, term) => {
    if (!term.trim() || !enableIndexing || !stableSearchFields.length) {
      return dataArray;
    }

    const termLower = term.toLowerCase();
    const matchingIndices = new Set();

    // Use n-gram index for fast searching
    if (termLower.length >= 3) {
      for (let i = 0; i < termLower.length - 2; i++) {
        const ngram = termLower.slice(i, i + 3);
        const indices = searchIndexRef.current.get(ngram);
        if (indices) {
          indices.forEach(idx => matchingIndices.add(idx));
        }
      }
    }

    // Fallback to linear search for short terms
    if (matchingIndices.size === 0) {
      dataArray.forEach((item, idx) => {
        const searchableText = stableSearchFields
          .map(field => getNestedValue(item, field))
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        
        if (searchableText.includes(termLower)) {
          matchingIndices.add(idx);
        }
      });
    }

    return Array.from(matchingIndices).map(idx => dataArray[idx]);
  }, [stableSearchFields, enableIndexing, getNestedValue]);

  // Advanced filtering with caching
  const filterData = useCallback((dataArray, filterConfig) => {
    const filterKey = JSON.stringify(filterConfig);
    
    if (enableCaching && filterCacheRef.current.has(filterKey)) {
      return filterCacheRef.current.get(filterKey);
    }

    const filtered = dataArray.filter(item => {
      return Object.entries(filterConfig).every(([field, value]) => {
        if (!value || value === 'all') return true;
        
        const itemValue = getNestedValue(item, field);
        
        // Handle different filter types
        if (Array.isArray(value)) {
          return value.includes(itemValue);
        }
        
        if (typeof value === 'object' && value.min !== undefined) {
          const numValue = Number(itemValue);
          return numValue >= value.min && numValue <= value.max;
        }
        
        return String(itemValue).toLowerCase().includes(String(value).toLowerCase());
      });
    });

    if (enableCaching) {
      filterCacheRef.current.set(filterKey, filtered);
    }
    
    return filtered;
  }, [enableCaching, getNestedValue]);

  // Advanced sorting with caching
  const sortData = useCallback((dataArray, sortField, direction) => {
    if (!sortField) return dataArray;
    
    const sortKey = `${sortField}-${direction}`;
    
    if (enableCaching && sortCacheRef.current.has(sortKey)) {
      return sortCacheRef.current.get(sortKey);
    }

    const sorted = [...dataArray].sort((a, b) => {
      const aValue = getNestedValue(a, sortField);
      const bValue = getNestedValue(b, sortField);
      
      // Handle different data types
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return direction === 'asc' ? aValue - bValue : bValue - aValue;
      }
      
      if (aValue instanceof Date && bValue instanceof Date) {
        return direction === 'asc' ? aValue - bValue : bValue - aValue;
      }
      
      const aStr = String(aValue || '').toLowerCase();
      const bStr = String(bValue || '').toLowerCase();
      
      if (direction === 'asc') {
        return aStr.localeCompare(bStr);
      } else {
        return bStr.localeCompare(aStr);
      }
    });

    if (enableCaching) {
      sortCacheRef.current.set(sortKey, sorted);
    }
    
    return sorted;
  }, [enableCaching, getNestedValue]);

  // Main data processing pipeline
  useEffect(() => {
    const processData = async () => {
      setLoading(true);
      
      try {
        // Process in chunks to avoid blocking UI
        await new Promise(resolve => setTimeout(resolve, 0));
        
        let processed = [...data];
        
        // Apply search inline to avoid callback dependencies
        if (searchTerm.trim()) {
          const termLower = searchTerm.toLowerCase();
          
          if (!enableIndexing || !stableSearchFields.length) {
            // Simple search without indexing
            processed = processed.filter(item => {
              const searchableText = stableSearchFields
                .map(field => {
                  // Inline getNestedValue to avoid dependency
                  return field.split('.').reduce((current, key) => current?.[key], item);
                })
                .filter(Boolean)
                .join(' ')
                .toLowerCase();
              return searchableText.includes(termLower);
            });
          } else {
            // Use n-gram index for fast searching
            const matchingIndices = new Set();
            
            if (termLower.length >= 3) {
              for (let i = 0; i < termLower.length - 2; i++) {
                const ngram = termLower.slice(i, i + 3);
                const indices = searchIndexRef.current.get(ngram);
                if (indices) {
                  indices.forEach(idx => matchingIndices.add(idx));
                }
              }
            }

            // Fallback to linear search for short terms or if no index matches
            if (matchingIndices.size === 0) {
              processed.forEach((item, idx) => {
                const searchableText = stableSearchFields
                  .map(field => {
                    // Inline getNestedValue to avoid dependency
                    return field.split('.').reduce((current, key) => current?.[key], item);
                  })
                  .filter(Boolean)
                  .join(' ')
                  .toLowerCase();
                
                if (searchableText.includes(termLower)) {
                  matchingIndices.add(idx);
                }
              });
            }

            processed = Array.from(matchingIndices).map(idx => processed[idx]);
          }
        }
        
        // Apply filters inline
        if (Object.keys(filters).length > 0) {
          processed = processed.filter(item => {
            return Object.entries(filters).every(([field, value]) => {
              if (!value || value === 'all') return true;
              
              // Inline getNestedValue to avoid dependency
              const itemValue = field.split('.').reduce((current, key) => current?.[key], item);
              
              // Handle different filter types
              if (Array.isArray(value)) {
                return value.includes(itemValue);
              }
              
              if (typeof value === 'object' && value.min !== undefined) {
                const numValue = Number(itemValue);
                return numValue >= value.min && numValue <= value.max;
              }
              
              return String(itemValue).toLowerCase().includes(String(value).toLowerCase());
            });
          });
        }
        
        // Apply sorting inline
        if (sortConfig.field) {
          processed = [...processed].sort((a, b) => {
            // Inline getNestedValue to avoid dependency
            const aValue = sortConfig.field.split('.').reduce((current, key) => current?.[key], a);
            const bValue = sortConfig.field.split('.').reduce((current, key) => current?.[key], b);
            
            // Handle different data types
            if (typeof aValue === 'number' && typeof bValue === 'number') {
              return sortConfig.direction === 'asc' ? aValue - bValue : bValue - aValue;
            }
            
            if (aValue instanceof Date && bValue instanceof Date) {
              return sortConfig.direction === 'asc' ? aValue - bValue : bValue - aValue;
            }
            
            const aStr = String(aValue || '').toLowerCase();
            const bStr = String(bValue || '').toLowerCase();
            
            if (sortConfig.direction === 'asc') {
              return aStr.localeCompare(bStr);
            } else {
              return bStr.localeCompare(aStr);
            }
          });
        }
        
        setFilteredData(processed);
        
      } finally {
        setLoading(false);
      }
    };

    processData();
  }, [data, searchTerm, filters, sortConfig, enableIndexing, stableSearchFields]);

  // Paginated data
  const paginatedData = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    return filteredData.slice(startIndex, endIndex);
  }, [filteredData, currentPage, pageSize]);

  // Pagination info
  const paginationInfo = useMemo(() => {
    const totalPages = Math.ceil(filteredData.length / pageSize);
    return {
      currentPage,
      totalPages,
      totalItems: filteredData.length,
      startItem: (currentPage - 1) * pageSize + 1,
      endItem: Math.min(currentPage * pageSize, filteredData.length),
      hasPrevious: currentPage > 1,
      hasNext: currentPage < totalPages
    };
  }, [filteredData.length, currentPage, pageSize]);

  // Selection management
  const toggleSelection = useCallback((itemId) => {
    setSelectedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(itemId)) {
        newSet.delete(itemId);
      } else {
        newSet.add(itemId);
      }
      return newSet;
    });
  }, []);

  const selectAll = useCallback((pageOnly = false) => {
    const itemsToSelect = pageOnly ? paginatedData : filteredData;
    const newIds = itemsToSelect.map(item => item.id).filter(Boolean);
    setSelectedItems(prev => new Set([...prev, ...newIds]));
  }, [paginatedData, filteredData]);

  const clearSelection = useCallback(() => {
    setSelectedItems(new Set());
  }, []);

  // Update search
  const updateSearch = useCallback((term) => {
    setSearchTerm(term);
    setCurrentPage(1);
  }, []);

  // Update filters
  const updateFilter = useCallback((field, value) => {
    setFilters(prev => ({ ...prev, [field]: value }));
    setCurrentPage(1);
  }, []);

  // Update sorting
  const updateSort = useCallback((field) => {
    setSortConfig(prev => ({
      field,
      direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  }, []);

  // Clear all filters
  const clearFilters = useCallback(() => {
    setFilters({});
    setSearchTerm('');
    setCurrentPage(1);
  }, []);

  // Update data and rebuild indices
  const updateData = useCallback((newData) => {
    setData(newData);
    setCurrentPage(1);
    clearSelection();
    
    // Clear caches
    filterCacheRef.current.clear();
    sortCacheRef.current.clear();
    
    // Rebuild search index inline
    if (enableIndexing && stableSearchFields.length) {
      const index = new Map();
      newData.forEach((item, idx) => {
        const searchableText = stableSearchFields
          .map(field => {
            // Inline getNestedValue to avoid dependency
            return field.split('.').reduce((current, key) => current?.[key], item);
          })
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        
        // Create n-gram index for fast partial matching
        const words = searchableText.split(/\s+/);
        words.forEach(word => {
          if (word.length > 2) {
            for (let i = 0; i < word.length - 2; i++) {
              const ngram = word.slice(i, i + 3);
              if (!index.has(ngram)) {
                index.set(ngram, new Set());
              }
              index.get(ngram).add(idx);
            }
          }
        });
      });
      searchIndexRef.current = index;
    }
    
    // Chunk data inline
    if (enableVirtualization) {
      const chunks = [];
      for (let i = 0; i < newData.length; i += chunkSize) {
        chunks.push(newData.slice(i, i + chunkSize));
      }
      dataChunksRef.current = chunks;
    }
  }, [enableIndexing, stableSearchFields, enableVirtualization, chunkSize, clearSelection]);

  // Initialize
  useEffect(() => {
    if (data.length > 0) {
      // Build search index inline
      if (enableIndexing && stableSearchFields.length) {
        const index = new Map();
        data.forEach((item, idx) => {
          const searchableText = stableSearchFields
            .map(field => {
              // Inline getNestedValue to avoid dependency
              return field.split('.').reduce((current, key) => current?.[key], item);
            })
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          
          // Create n-gram index for fast partial matching
          const words = searchableText.split(/\s+/);
          words.forEach(word => {
            if (word.length > 2) {
              for (let i = 0; i < word.length - 2; i++) {
                const ngram = word.slice(i, i + 3);
                if (!index.has(ngram)) {
                  index.set(ngram, new Set());
                }
                index.get(ngram).add(idx);
              }
            }
          });
        });
        searchIndexRef.current = index;
      }
      
      // Chunk data inline
      if (enableVirtualization) {
        const chunks = [];
        for (let i = 0; i < data.length; i += chunkSize) {
          chunks.push(data.slice(i, i + chunkSize));
        }
        dataChunksRef.current = chunks;
      }
    }
  }, [data, enableIndexing, stableSearchFields, enableVirtualization, chunkSize]);

  // Reset to first page when filtered data changes and current page is out of bounds
  useEffect(() => {
    const totalPages = Math.ceil(filteredData.length / pageSize);
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(1);
    }
  }, [filteredData.length, currentPage, pageSize]);

  // Performance stats
  const performanceStats = useMemo(() => ({
    totalRecords: data.length,
    filteredRecords: filteredData.length,
    selectedRecords: selectedItems.size,
    searchIndexSize: searchIndexRef.current.size,
    filterCacheSize: filterCacheRef.current.size,
    sortCacheSize: sortCacheRef.current.size,
    chunksCount: dataChunksRef.current.length
  }), [data.length, filteredData.length, selectedItems.size]);

  return {
    // Data
    data: paginatedData,
    allData: filteredData,
    rawData: data,
    
    // State
    loading,
    searchTerm,
    filters,
    sortConfig,
    selectedItems,
    
    // Pagination
    pagination: paginationInfo,
    setCurrentPage,
    setPageSize,
    
    // Actions
    updateData,
    updateSearch,
    updateFilter,
    updateSort,
    clearFilters,
    
    // Selection
    toggleSelection,
    selectAll,
    clearSelection,
    
    // Performance
    stats: performanceStats,
    
    // Utilities
    getNestedValue
  };
};

// Custom hook for real-time data streaming
export const useRealTimeData = (
  dataSource,
  updateInterval = 5000,
  maxBuffer = 10000
) => {
  const [streamData, setStreamData] = useState([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const intervalRef = useRef();
  const bufferRef = useRef([]);

  const startStreaming = useCallback(() => {
    setIsStreaming(true);
    
    intervalRef.current = setInterval(async () => {
      try {
        const newData = await dataSource();
        
        if (Array.isArray(newData)) {
          bufferRef.current = [...bufferRef.current, ...newData];
          
          // Maintain buffer size
          if (bufferRef.current.length > maxBuffer) {
            bufferRef.current = bufferRef.current.slice(-maxBuffer);
          }
          
          setStreamData([...bufferRef.current]);
        }
      } catch (error) {
        console.error('Streaming error:', error);
      }
    }, updateInterval);
  }, [dataSource, updateInterval, maxBuffer]);

  const stopStreaming = useCallback(() => {
    setIsStreaming(false);
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
    }
  }, []);

  const clearBuffer = useCallback(() => {
    bufferRef.current = [];
    setStreamData([]);
  }, []);

  useEffect(() => {
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  return {
    data: streamData,
    isStreaming,
    startStreaming,
    stopStreaming,
    clearBuffer,
    bufferSize: bufferRef.current.length
  };
};

export default useAdvancedDataManagement;
